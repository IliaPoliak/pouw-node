//! Block production and the work worker, so searching, proving and work checks never
//! block the loop.
//!
//! # The work worker
//!
//! One thread owns the [`Prover`] and runs every [`WorkJob`] the loop hands it:
//! [`WorkJob::SearchNonce`] tries a range of nonces, [`WorkJob::Prove`] makes a proof
//! and [`WorkJob::VerifyWork`] checks the work claim of a received block. The answer is
//! a [`WorkDone`] on the work channel.
//!
//! One job is in flight at a time, and the loop owns that fact: [`Work::in_flight`]
//! names the job from `send` until its [`WorkDone`] is handled. The loop sends a job
//! on the jobs channel (capacity [`JOBS_CAPACITY`](crate::node::JOBS_CAPACITY)) and the
//! worker answers on the work channel (capacity
//! [`WORK_CAPACITY`](crate::node::WORK_CAPACITY)), which the loop reads second, after
//! control. Because the loop sends no second job before the first result is handled,
//! neither channel can overflow: the worker blocks on a send that has room.
//!
//! When the worker is free, [`dispatch`] picks the next job by priority: a received
//! block to verify, then a proof for a pending request, then a nonce range of the block
//! template.
//!
//! # Mining
//!
//! The consensus of header v1 is hash proof of work, so a block needs no proof tx and
//! mining never waits for a request. A proof is a fee-paying payload: while a request
//! is pending and no proof is held, the worker proves it, and the finished proof is
//! kept in [`Work::held`] until the next template takes it. The proof binds the parent
//! and the coin transactions of its block through eta, so the held proof carries the
//! exact transactions it was made for. It is dropped when the tip moves or its request
//! leaves the mempool. A request whose proof failed, or whose circuit the chain does
//! not know, is set aside in [`Work::skipped`] until the tip changes, so one bad
//! request does not keep the worker from searching.
//!
//! The template ([`Template`]) is the coin transactions by fee rate ([`candidate`]) and
//! at most the held proof. It is rebuilt when the tip changes, when the held proof
//! appears or goes, when the mempool has grown and [`TEMPLATE_REFRESH_SECS`] passed
//! since the build, and when the nonce range is exhausted (the timestamp moves on). The
//! header takes its target and timestamp floor from [`chain::child_rules`], the code
//! that checks the header of a received block, and its timestamp from the clock of the
//! node, at least the median time past plus one.
//!
//! A search job covers [`SEARCH_BATCH`] nonces. On a found nonce [`on_nonce`] encodes
//! the block, runs `precheck::check_block` and `chain::receive_block`, and announces the
//! header with `p2p::Gossip::Announce`. Peers fetch the body with `GetBlocks`.
//!
//! The account model has no coinbase transaction: when a block connects, the reward
//! `subsidy(height)` plus the fees of the block is credited to `header.miner` by
//! `pouw_consensus::apply_block`, which is part of the pouw-node#77 spec.
//!
//! # Verify-work
//!
//! The work claim of a block is checked by [`pouw_consensus::verify_pow`]. In header v1
//! it is the cheap header check that the precheck runs already. A version whose claim is
//! costly to check leaves it out of the precheck, and received blocks reach the worker
//! through [`Work::verify_queue`], a queue of [`VERIFY_QUEUE_CAP`] blocks. A block that
//! finds the queue full is dropped and counted in `Metrics::dropped_blocks`, its peer
//! is not penalised. Blocks arrive only as answers to `GetBlocks` ([`enqueue_verify`]
//! is called from `node::connect_synced`).

use std::{
    cmp::Reverse,
    collections::{BTreeSet, BinaryHeap, VecDeque},
};

use pouw_consensus::{
    ConsensusParams, InvalidBlock, Scratch, StateError, StateView, pow::meets, transition::cost,
    verify_pow,
};
use pouw_crypto::{Address, FieldInput, Hash32};
use pouw_provers::{Prover, ProverError, Statement};
use pouw_types::{
    Amount, Block, BlockHeader, BlockId, FastMap, PowNonce, ProofTx, SignedTx, Timestamp, TxId,
    TxKind, U64, UsageCounter, block_id, eta_chain, mask,
    protocol::{
        BLOCK_VERSION, MAX_BLOCK_BYTES, MAX_PROOF_BYTES, MAX_PROOFS_PER_BLOCK, MAX_TXS_PER_BLOCK,
    },
    txid,
};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::{
    chain::{self, BlockOutcome, ChildRules},
    mempool::{self, FeeRate, Mempool, Pending},
    node::{ComponentFault, NodeFault, NodeState},
    p2p::{Command, Gossip, PeerIx, limits::MAX_BLOCKS_PER_REQUEST, send as send_command},
    precheck::{self, CheckedAnnounce, CheckedBlock},
    store::{self, StoreError},
};

/// Nonces one [`WorkJob::SearchNonce`] tries, the longest a new tip or a received block
/// waits for the worker. One header hash takes about 0.35 us in a release build (2.9
/// million per second, measured on the development machine), so this is about 46 ms.
pub const SEARCH_BATCH: u64 = 131_072;

/// Seconds after which a template is rebuilt to take the transactions that reached the
/// mempool since its build.
pub const TEMPLATE_REFRESH_SECS: u64 = 5;

/// Blocks waiting for the worker: one answer to `GetBlocks` fits whole, so a valid
/// chain from one peer is never dropped. Each block is at most `MAX_BLOCK_BYTES` (8 MiB),
/// so the queue holds at most 128 MiB.
pub const VERIFY_QUEUE_CAP: usize = MAX_BLOCKS_PER_REQUEST;

/// One job for the work worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkJob {
    /// Tries a range of nonces of one header.
    SearchNonce(Box<SearchJob>),
    /// Makes one proof.
    Prove(Box<ProofJob>),
    /// Checks the work claim of a received block.
    VerifyWork(Box<CheckedBlock>),
}

/// The nonces `start..start + count` of `header`, tried in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchJob {
    /// The template the header comes from, echoed in [`NonceDone`].
    pub key: u64,
    pub header: BlockHeader,
    pub start: u64,
    pub count: u64,
}

/// The answer to a [`WorkJob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkDone {
    Nonce(NonceDone),
    Proof(ProofDone),
    /// The work claim of the block and its verdict.
    Verified(Box<VerifiedWork>),
}

/// A [`SearchJob`] that is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NonceDone {
    pub key: u64,
    /// The first nonce in the range whose block id is at most the target.
    pub found: Option<PowNonce>,
    /// Where the next range starts. `u64::MAX` means the nonces are used up.
    pub next_start: u64,
    /// Nonces tried in the range: up to and including the found one, else all.
    pub attempts: u64,
}

/// A block back from [`WorkJob::VerifyWork`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedWork {
    pub block: CheckedBlock,
    pub verdict: Result<(), InvalidBlock>,
}

/// One proof for the work worker to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofJob {
    /// The proof request.
    pub request: TxId,
    /// The circuit as registered; the worker derives the proving key from it.
    pub circuit: Box<[u8]>,
    pub eta: Hash32,
    pub mask: Hash32,
    /// `public_inputs` of the request.
    pub client_inputs: Vec<FieldInput>,
    pub witness: Box<[u8]>,
}

/// A finished [`ProofJob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofDone {
    pub request: TxId,
    pub proof: Result<Box<[u8]>, ProverError>,
}

/// The job the worker has, and what the loop needs to know about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InFlight {
    /// A proof for this request.
    Prove(Box<Plan>),
    /// A nonce range of the template with this key.
    Search(u64),
    /// The block with this id, received from `peer`.
    Verify { id: BlockId, peer: PeerIx },
}

/// What a proof is made for: the block it can join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub request: SignedTx,
    /// The tip the proof binds through eta.
    pub parent: BlockId,
    /// The coin transactions the proof binds through eta.
    pub coin_txs: Vec<SignedTx>,
    pub counter: UsageCounter,
}

/// A made proof waiting for the next template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub parent: BlockId,
    pub coin_txs: Vec<SignedTx>,
    pub proof_tx: ProofTx,
}

/// The block being mined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
    pub key: u64,
    /// The block with nonce 0.
    pub block: Block,
    /// First nonce of the next range.
    pub next_start: u64,
    /// The clock at the build.
    pub built_at: Timestamp,
    /// Mempool size at the build.
    pub pool_len: usize,
}

/// A received block waiting for the worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queued {
    pub peer: PeerIx,
    pub block: CheckedBlock,
}

/// The state of the work slot, mining and the verify queue. Owned by the loop.
#[derive(Debug)]
pub struct Work {
    pub jobs: mpsc::Sender<WorkJob>,
    pub in_flight: Option<InFlight>,
    pub verify_queue: VecDeque<Queued>,
    pub held: Option<Held>,
    /// Requests not to prove at the current tip.
    pub skipped: BTreeSet<TxId>,
    pub template: Option<Template>,
    /// The tip the miner last saw.
    pub tip: Option<BlockId>,
    /// The key of the next template.
    pub next_key: u64,
}

pub fn new_work(jobs: mpsc::Sender<WorkJob>) -> Work {
    Work {
        jobs,
        in_flight: None,
        verify_queue: VecDeque::new(),
        held: None,
        skipped: BTreeSet::new(),
        template: None,
        tip: None,
        next_key: 0,
    }
}

/// The work worker: runs every job of `jobs` and sends the result on `work`. It ends
/// when the loop drops the job sender, and with a fault when the loop is gone while a
/// result is ready.
pub fn run_work_worker(
    prover: &Prover,
    params: &ConsensusParams,
    mut jobs: mpsc::Receiver<WorkJob>,
    work: &mpsc::Sender<WorkDone>,
) -> Result<(), ComponentFault> {
    info!(?prover, "work worker ready");
    while let Some(job) = jobs.blocking_recv() {
        work.blocking_send(run_job(prover, params, job))
            .map_err(|mpsc::error::SendError(_)| ComponentFault::NodeGone)?;
    }
    Ok(())
}

pub fn run_job(prover: &Prover, params: &ConsensusParams, job: WorkJob) -> WorkDone {
    match job {
        WorkJob::SearchNonce(job) => WorkDone::Nonce(search_nonce(&job)),
        WorkJob::Prove(job) => WorkDone::Proof(prove(prover, &job)),
        WorkJob::VerifyWork(block) => WorkDone::Verified(Box::new(verify_work(params, *block))),
    }
}

#[cfg(test)]
thread_local! {
    static CANDIDATE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many times [`candidate`] ran on this thread.
#[cfg(test)]
pub(crate) fn candidate_calls() -> usize {
    CANDIDATE_CALLS.with(std::cell::Cell::get)
}

/// Tries the nonces of the range in order and stops at the first block id that is at
/// most the target. The range ends before `u64::MAX`.
pub fn search_nonce(job: &SearchJob) -> NonceDone {
    let end = job.start.saturating_add(job.count);
    let mut header = job.header;
    for nonce in job.start..end {
        header.nonce = U64::new(nonce);
        if meets(&block_id(&header), &header.target) {
            return NonceDone {
                key: job.key,
                found: Some(PowNonce(nonce)),
                next_start: end,
                attempts: nonce.saturating_sub(job.start).saturating_add(1),
            };
        }
    }
    NonceDone {
        key: job.key,
        found: None,
        next_start: end,
        attempts: end.saturating_sub(job.start),
    }
}

/// The verify-work stage of a received block, run by the work worker so that a costly
/// check never blocks the loop (plan D5, stage 3). It checks the proof of work claim with
/// [`verify_pow`] and accepts the payload.
///
/// The proofs of the proof txs are not verified here. `pouw_consensus::apply_block`
/// verifies them when the block connects (pouw-node#77, rule 9), against the state of the
/// parent. A work job would need the verifying keys read when the block is queued, and
/// that state can differ from the parent's: a circuit registered by an earlier block
/// still in the queue, or only on a side branch, has no key there, so its proof would
/// be skipped and the block would pass unverified. The price is one `Prover::verify` per
/// proof tx on the loop thread when the block connects.
///
/// The block of an ancestor of `NodeState::assume_valid` is not queued for this stage in
/// initial block download (`docs/CHAINSPEC.md`, `ibd::on_headers`). Its proofs are still
/// verified when it connects: skipping those is a change of `pouw_consensus::apply_block`,
/// not of the download.
pub fn verify_work(params: &ConsensusParams, block: CheckedBlock) -> VerifiedWork {
    let verdict = verify_pow(params, &block.block.header, &block.block)
        .map(drop)
        .map_err(InvalidBlock::from);
    VerifiedWork { block, verdict }
}

pub fn prove(prover: &Prover, job: &ProofJob) -> ProofDone {
    let statement = Statement::new(&job.eta, &job.mask, &job.client_inputs);
    let proof = prover
        .setup(&job.circuit)
        .and_then(|keys| prover.prove(&keys.proving_key, &statement, &job.witness));
    ProofDone {
        request: job.request,
        proof,
    }
}

/// Which proof requests [`candidate`] may take.
#[derive(Debug, Clone, Copy)]
pub enum Requests<'a> {
    /// The block carries no proof.
    Skip,
    /// The block carries the best paying request not in `excluding`.
    Take { excluding: &'a BTreeSet<TxId> },
}

/// What the next block takes from the mempool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate<'p> {
    /// The proof request the block proves, with its id.
    pub request: Option<(&'p TxId, &'p SignedTx)>,
    /// The `Transfer` and `RegisterCircuit` transactions of `txs`, in an order that
    /// applies: for every sender the nonces ascend with no gap, and the nonce before the
    /// first is the one of the account at the tip.
    pub coin_txs: Vec<&'p SignedTx>,
}

/// The limits a block template stays within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockCaps {
    /// Most borsh bytes of the whole block.
    pub max_bytes: usize,
    /// Most entries of `txs` and `proof_txs` together.
    pub max_txs: usize,
}

/// The consensus limits of a block.
pub const PROTOCOL_CAPS: BlockCaps = BlockCaps {
    max_bytes: MAX_BLOCK_BYTES,
    max_txs: MAX_TXS_PER_BLOCK,
};

/// Bytes of a block that no transaction accounts for: the header and the length prefix
/// of `txs` and of `proof_txs`.
const BASE_BYTES: usize = BlockHeader::SIZE + 4 + 4;

/// The proof entry beyond its request: the usage counter and a proof of the largest
/// size. Selection reserves it up front for a block with a proof, so the request chosen
/// later always fits.
const PROOF_OVERHEAD_BYTES: usize = 8 + 4 + MAX_PROOF_BYTES;

/// Chooses the transactions of the next block from the pool by fee rate, highest first,
/// within `caps`.
///
/// - `state` gives the next nonce of every account at the tip. A transaction is
///   selectable when it carries that nonce or follows a selected transaction of its
///   sender, so a nonce gap or a stale nonce keeps a transaction out of the template.
/// - The candidates are a max-heap by `FeeRate`, seeded with the first selectable
///   transaction of every sender. Taking one pushes its sender's next nonce. The pool
///   index `by_fee` is not walked from the top, because a high paying transaction behind
///   a low paying predecessor must wait for it.
/// - With [`Requests::Take`] the block's request is the best paying proof request met, a
///   later one replacing it when it pays a higher rate and fits. `txs` are applied
///   before `proof_txs`, so a request ends the selectable chain of its sender. With
///   [`Requests::Skip`] a request is passed over the same way.
/// - A transaction is taken only when its sender can pay it: the balances start at the
///   tip and every taken transaction takes its amount and fee from its sender and gives
///   the amount of a transfer to its receiver, in the order `apply_block` applies them. An
///   unaffordable transaction is skipped with the rest of its sender's chain, so the
///   template never holds a transaction `apply_block` would reject.
/// - Until a request is held, a coin transaction is taken only when the smallest request
///   of the pool still fits after it.
/// - A transaction that does not fit the bytes left or the count left is skipped with
///   the rest of its sender's chain, and smaller transactions of other senders may still
///   fit.
///
/// A store failure while reading an account is returned.
pub fn candidate<'p, V: StateView + ?Sized>(
    pool: &'p Mempool,
    state: &V,
    caps: &BlockCaps,
    requests: Requests<'_>,
) -> Result<Candidate<'p>, StateError> {
    #[cfg(test)]
    CANDIDATE_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
    let (framing, coin_cap) = match requests {
        Requests::Skip => (BASE_BYTES, caps.max_txs),
        Requests::Take { .. } => (
            BASE_BYTES.saturating_add(PROOF_OVERHEAD_BYTES),
            caps.max_txs.saturating_sub(MAX_PROOFS_PER_BLOCK),
        ),
    };
    let Some(mut room) = caps.max_bytes.checked_sub(framing) else {
        return Ok(Candidate {
            request: None,
            coin_txs: Vec::new(),
        });
    };
    let takes = |id: &TxId| match requests {
        Requests::Skip => false,
        Requests::Take { excluding } => !excluding.contains(id),
    };
    let mut ready = BinaryHeap::new();
    for (sender, queue) in &pool.senders {
        let next = state.account(sender)?.unwrap_or_default().nonce;
        ready.extend(queue.get(&next).and_then(|id| ready_entry(pool, id)));
    }
    let smallest_request = pool
        .txs
        .iter()
        .filter(|(id, pending)| {
            matches!(pending.tx.body.kind, TxKind::ProofRequest { .. }) && takes(id)
        })
        .map(|(_, pending)| pending.bytes)
        .min()
        .unwrap_or(0);
    let mut request: Option<(&TxId, &Pending)> = None;
    let mut coin_txs = Vec::new();
    let mut balances = Balances {
        state,
        left: FastMap::default(),
    };
    while let Some(Ready {
        id: Reverse(id), ..
    }) = ready.pop()
    {
        let Some((id, pending)) = pool.txs.get_key_value(&id) else {
            continue;
        };
        let body = &pending.tx.body;
        if matches!(body.kind, TxKind::ProofRequest { .. }) {
            if !takes(id) {
                continue;
            }
            if !balances.covers(body)? {
                continue;
            }
            let held = request.map_or(0, |(_, held)| held.bytes);
            let better = request.is_none_or(|(_, held)| pending.rate > held.rate);
            let left = room
                .checked_add(held)
                .and_then(|free| free.checked_sub(pending.bytes));
            if let (true, Some(left)) = (better, left) {
                request = Some((id, pending));
                room = left;
            }
            continue;
        }
        let kept_for_request = if request.is_some() {
            0
        } else {
            smallest_request
        };
        let Some(left) = room
            .checked_sub(pending.bytes)
            .filter(|left| *left >= kept_for_request)
        else {
            continue;
        };
        if coin_txs.len() >= coin_cap || !balances.covers(body)? {
            continue;
        }
        balances.apply(body)?;
        room = left;
        coin_txs.push(&pending.tx);
        let following = body
            .nonce
            .checked_next()
            .and_then(|next| pool.senders.get(&body.sender)?.get(&next));
        ready.extend(following.and_then(|following| ready_entry(pool, following)));
    }
    Ok(Candidate {
        request: request.map(|(id, pending)| (id, &pending.tx)),
        coin_txs,
    })
}

/// What the balances of the accounts are after the transactions selected so far, read
/// from the state at the tip the first time an account is met.
struct Balances<'v, V: StateView + ?Sized> {
    state: &'v V,
    left: FastMap<Address, Amount>,
}

impl<V: StateView + ?Sized> Balances<'_, V> {
    fn get(&mut self, address: &Address) -> Result<Amount, StateError> {
        if let Some(amount) = self.left.get(address) {
            return Ok(*amount);
        }
        let amount = self.state.account(address)?.unwrap_or_default().balance;
        self.left.insert(*address, amount);
        Ok(amount)
    }

    /// Whether the sender of `body` can pay its amount and fee now.
    fn covers(&mut self, body: &pouw_types::TxBody) -> Result<bool, StateError> {
        let Some(needed) = cost(body) else {
            return Ok(false);
        };
        Ok(self.get(&body.sender)? >= needed)
    }

    /// Takes the cost of `body` from its sender and gives the amount of a transfer to
    /// its receiver. Only called after [`Self::covers`].
    fn apply(&mut self, body: &pouw_types::TxBody) -> Result<(), StateError> {
        let Some(needed) = cost(body) else {
            return Ok(());
        };
        let held = self.get(&body.sender)?;
        if let Some(rest) = held.checked_sub(needed) {
            self.left.insert(body.sender, rest);
        }
        if let TxKind::Transfer { to, amount } = &body.kind {
            let had = self.get(to)?;
            // An overflow keeps the lower balance, which only skips more.
            if let Some(sum) = had.checked_add(*amount) {
                self.left.insert(*to, sum);
            }
        }
        Ok(())
    }
}

/// A selectable transaction in the heap of [`candidate`]: the best rate first, the
/// lowest txid among equal rates so the choice does not depend on map order.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Ready {
    rate: FeeRate,
    id: Reverse<TxId>,
}

fn ready_entry(pool: &Mempool, id: &TxId) -> Option<Ready> {
    let pending = pool.txs.get(id)?;
    Some(Ready {
        rate: pending.rate,
        id: Reverse(*id),
    })
}

/// Sends `job` to the worker and records it in the slot. The worker being gone is a
/// [`NodeFault::ProverGone`]. The slot is free by the caller's check, so the channel has
/// room.
fn send(work: &mut Work, job: WorkJob, slot: InFlight) -> Result<(), NodeFault> {
    match work.jobs.try_send(job) {
        Ok(()) => {
            work.in_flight = Some(slot);
            Ok(())
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            warn!("the jobs channel is full while no job is in flight");
            Ok(())
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(NodeFault::ProverGone),
    }
}

/// Queues a received block for its work check and wakes the worker. A block that finds
/// the queue full is dropped and counted, the peer is not penalised: the node is busy,
/// the block is not wrong.
pub fn enqueue_verify(
    state: &mut NodeState,
    peer: PeerIx,
    block: CheckedBlock,
) -> Result<(), NodeFault> {
    if state.work.verify_queue.len() >= VERIFY_QUEUE_CAP {
        state.metrics.dropped_blocks = state.metrics.dropped_blocks.saturating_add(1);
        warn!(?peer, "the verify queue is full, a block is dropped");
        return Ok(());
    }
    state.work.verify_queue.push_back(Queued { peer, block });
    dispatch(state)
}

/// What the miner reads from the store in one pass.
struct Tip {
    id: BlockId,
    height: u64,
    rules: ChildRules,
}

fn read_tip(state: &NodeState) -> Result<Option<Tip>, StoreError> {
    let reader = store::read(&state.store)?;
    let Some(tip) = store::tip(&reader)? else {
        return Ok(None);
    };
    let Some(rules) = chain::child_rules(&reader, &state.params, &tip.id)? else {
        return Ok(None);
    };
    Ok(Some(Tip {
        id: tip.id,
        height: tip.height.0,
        rules,
    }))
}

/// Gives the idle worker its next job: a received block, then a proof, then a nonce
/// range. Does nothing while a job is in flight. Every tick calls it too, so a template
/// that went stale is rebuilt and a miner that waited for the clock resumes.
pub fn dispatch(state: &mut NodeState) -> Result<(), NodeFault> {
    if state.work.in_flight.is_some() {
        return Ok(());
    }
    if let Some(Queued { peer, block }) = state.work.verify_queue.pop_front() {
        let id = block_id(&block.block.header);
        let slot = InFlight::Verify { id, peer };
        return send(&mut state.work, WorkJob::VerifyWork(Box::new(block)), slot);
    }
    let Some(miner) = state.miner else {
        return Ok(());
    };
    let Some(tip) = read_tip(state)? else {
        return Ok(());
    };
    follow_tip(state, &tip);
    if state.work.held.is_none()
        && has_untried_request(state)
        && let Some((plan, job)) = plan_proof(state, &tip, &miner)?
    {
        return send(
            &mut state.work,
            WorkJob::Prove(Box::new(job)),
            InFlight::Prove(Box::new(plan)),
        );
    }
    search(state, &tip, &miner)
}

/// Whether the mempool holds a proof request that is not in [`Work::skipped`], the
/// condition for [`candidate`] to run on the way to a proof job. It stops at the first
/// such request and reads no state.
fn has_untried_request(state: &NodeState) -> bool {
    mempool::proof_requests(&state.mempool).any(|(id, _)| !state.work.skipped.contains(id))
}

/// Drops what a new tip made stale: the skipped requests and a held proof of another
/// parent, and a held proof whose request left the mempool.
fn follow_tip(state: &mut NodeState, tip: &Tip) {
    if state.work.tip != Some(tip.id) {
        state.work.tip = Some(tip.id);
        state.work.skipped.clear();
    }
    let pool = &state.mempool;
    state.work.held.take_if(|held| {
        held.parent != tip.id || mempool::get(pool, &txid(&held.proof_tx.request)).is_none()
    });
}

/// Picks the request to prove and the block it joins. A request of an unknown circuit
/// is set aside and the next one is tried.
fn plan_proof(
    state: &mut NodeState,
    tip: &Tip,
    miner: &Address,
) -> Result<Option<(Plan, ProofJob)>, NodeFault> {
    loop {
        match pick_proof(state, tip, miner)? {
            Pick::Nothing => return Ok(None),
            Pick::Unknown(id) => {
                warn!(%id, "a pending request names a circuit the chain does not know");
                state.work.skipped.insert(id);
            }
            Pick::Job(picked) => return Ok(Some(*picked)),
        }
    }
}

enum Pick {
    Nothing,
    Unknown(TxId),
    Job(Box<(Plan, ProofJob)>),
}

fn pick_proof(state: &NodeState, tip: &Tip, miner: &Address) -> Result<Pick, StoreError> {
    let reader = store::read(&state.store)?;
    let requests = Requests::Take {
        excluding: &state.work.skipped,
    };
    let chosen = candidate(&state.mempool, &reader, &PROTOCOL_CAPS, requests)?;
    let Some((id, request)) = chosen.request else {
        return Ok(Pick::Nothing);
    };
    let TxKind::ProofRequest {
        circuit,
        public_inputs,
        witness,
    } = &request.body.kind
    else {
        return Ok(Pick::Unknown(*id));
    };
    let Some(entry) = reader.circuit(circuit)? else {
        return Ok(Pick::Unknown(*id));
    };
    let counter = match reader.usage_counter(miner, circuit)? {
        None => UsageCounter(0),
        Some(last) => match last.checked_next() {
            Some(next) => next,
            None => return Ok(Pick::Unknown(*id)),
        },
    };
    let coin_txs: Vec<SignedTx> = chosen.coin_txs.into_iter().cloned().collect();
    let proof_tx = ProofTx {
        request: request.clone(),
        usage_counter: counter,
        proof: Box::from([]),
    };
    let eta = first_eta(&tip.id, &tip.rules.parent, &coin_txs, &proof_tx);
    let job = ProofJob {
        request: *id,
        circuit: entry.circuit.clone(),
        eta,
        mask: mask(miner, circuit, counter),
        client_inputs: public_inputs.clone(),
        witness: witness.clone(),
    };
    let plan = Plan {
        request: request.clone(),
        parent: tip.id,
        coin_txs,
        counter,
    };
    Ok(Pick::Job(Box::new((plan, job))))
}

/// The eta of the one proof tx of a block over `coin_txs` on `parent`.
fn first_eta(
    parent: &BlockId,
    parent_header: &BlockHeader,
    coin_txs: &[SignedTx],
    proof_tx: &ProofTx,
) -> Hash32 {
    let body = Block {
        header: *parent_header,
        txs: coin_txs.to_vec(),
        proof_txs: vec![proof_tx.clone()],
    };
    let etas = eta_chain(parent, &body.compute_txs_root(), &body.proof_txs);
    etas.first().copied().unwrap_or(Hash32::ZERO)
}

/// Sends the next nonce range of the template, building the template first when it is
/// missing or stale. A template whose timestamp (at least the median time past plus one)
/// is beyond the clock plus `max_future_secs` would not connect, so no job is sent and
/// the next tick tries again.
fn search(state: &mut NodeState, tip: &Tip, miner: &Address) -> Result<(), NodeFault> {
    let now = (state.clock)();
    if needs_rebuild(state, tip, now) {
        let template = build_template(state, tip, miner, now)?;
        let limit = now.0.saturating_add(state.params.max_future_secs);
        if template.block.header.timestamp.get() > limit {
            state.work.template = None;
            debug!(
                height = tip.height,
                "the chain is ahead of the clock, no block is built"
            );
            return Ok(());
        }
        debug!(
            key = template.key,
            height = tip.height,
            "new block template"
        );
        state.work.template = Some(template);
    }
    let Some(template) = state.work.template.as_mut() else {
        return Ok(());
    };
    let job = SearchJob {
        key: template.key,
        header: template.block.header,
        start: template.next_start,
        count: SEARCH_BATCH,
    };
    let key = template.key;
    send(
        &mut state.work,
        WorkJob::SearchNonce(Box::new(job)),
        InFlight::Search(key),
    )
}

fn needs_rebuild(state: &NodeState, tip: &Tip, now: Timestamp) -> bool {
    let Some(template) = &state.work.template else {
        return true;
    };
    let carries = template.block.proof_txs.first().map(|proof| &proof.request);
    let holds = state.work.held.as_ref().map(|held| &held.proof_tx.request);
    let grown = state.mempool.txs.len() > template.pool_len
        && now.0 >= template.built_at.0.saturating_add(TEMPLATE_REFRESH_SECS);
    template.block.header.parent != tip.id
        || carries != holds
        || template.next_start == u64::MAX
        || grown
}

fn build_template(
    state: &mut NodeState,
    tip: &Tip,
    miner: &Address,
    now: Timestamp,
) -> Result<Template, NodeFault> {
    let (txs, proof_txs) = if let Some(held) = &state.work.held {
        (held.coin_txs.clone(), vec![held.proof_tx.clone()])
    } else {
        let reader = store::read(&state.store)?;
        let chosen = candidate(&state.mempool, &reader, &PROTOCOL_CAPS, Requests::Skip)
            .map_err(StoreError::State)?;
        let txs = chosen.coin_txs.into_iter().cloned().collect();
        (txs, Vec::new())
    };
    let floor = tip.rules.mtp.0.saturating_add(1);
    let previous = state
        .work
        .template
        .as_ref()
        .filter(|old| old.block.header.parent == tip.id && old.next_start == u64::MAX)
        .map_or(0, |old| old.block.header.timestamp.get().saturating_add(1));
    let timestamp = now.0.max(floor).max(previous);
    let mut block = Block {
        header: BlockHeader {
            version: pouw_types::U32::new(BLOCK_VERSION),
            chain_id: pouw_types::U32::new(state.params.chain_id.0),
            system_id: U64::new(0),
            height: U64::new(tip.height.saturating_add(1)),
            parent: tip.id,
            timestamp: U64::new(timestamp),
            miner: *miner,
            tx_root: Hash32::ZERO,
            target: tip.rules.target,
            nonce: U64::new(0),
        },
        txs,
        proof_txs,
    };
    block.header.tx_root = block.compute_tx_root();
    let key = state.work.next_key;
    state.work.next_key = key.saturating_add(1);
    Ok(Template {
        key,
        block,
        next_start: 0,
        built_at: now,
        pool_len: state.mempool.txs.len(),
    })
}

/// Handles a finished nonce range. A range of a template that is gone is dropped. A
/// found nonce seals the block: it is encoded, goes through `precheck::check_block` and
/// `chain::receive_block`, and its header is announced to the peers.
pub fn on_nonce(state: &mut NodeState, done: NonceDone) -> Result<(), NodeFault> {
    state.work.in_flight = None;
    state.metrics.lottery_attempts = state.metrics.lottery_attempts.saturating_add(done.attempts);
    let current = state
        .work
        .template
        .as_ref()
        .is_some_and(|template| template.key == done.key);
    if current {
        match done.found {
            Some(nonce) => seal(state, nonce)?,
            None => {
                if let Some(template) = state.work.template.as_mut() {
                    template.next_start = done.next_start;
                }
            }
        }
    }
    dispatch(state)
}

fn seal(state: &mut NodeState, nonce: PowNonce) -> Result<(), NodeFault> {
    let Some(template) = state.work.template.take() else {
        return Ok(());
    };
    let mut block = template.block;
    block.header.nonce = U64::new(nonce.0);
    let Ok(bytes) = borsh::to_vec(&block) else {
        warn!("a mined block does not encode");
        return Ok(());
    };
    let checked = match precheck::check_block(bytes, &state.params, &mut Scratch::default()) {
        Ok(checked) => checked,
        Err(error) => {
            warn!(%error, "a mined block fails the precheck");
            return Ok(());
        }
    };
    let outcome = chain::receive_block(
        &mut state.store,
        &mut state.mempool,
        &mut state.events,
        &mut state.metrics,
        &state.params,
        &state.prover,
        (state.clock)(),
        &checked,
    )?;
    let BlockOutcome::Connected(tip) = outcome else {
        warn!(?outcome, "a mined block did not connect");
        return Ok(());
    };
    info!(height = tip.height.0, id = %tip.id, "mined a block");
    let announce = CheckedAnnounce {
        header: block.header,
        id: tip.id,
    };
    let command = Command::Broadcast(Gossip::Announce(Box::new(announce)));
    send_command(&state.network, command, &mut state.metrics)?;
    Ok(())
}

/// Handles a finished proof: the proof is held for the next template, a failed one sets
/// its request aside until the tip changes.
pub fn on_proof(state: &mut NodeState, done: ProofDone) -> Result<(), NodeFault> {
    let slot = state.work.in_flight.take();
    let Some(InFlight::Prove(plan)) = slot else {
        warn!(request = %done.request, "a proof arrived with no proof in flight");
        return dispatch(state);
    };
    match done.proof {
        Ok(proof) => {
            let Plan {
                request,
                parent,
                coin_txs,
                counter,
            } = *plan;
            state.work.held = Some(Held {
                parent,
                coin_txs,
                proof_tx: ProofTx {
                    request,
                    usage_counter: counter,
                    proof,
                },
            });
        }
        Err(error) => {
            warn!(%error, request = %done.request, "the proof failed");
            state.work.skipped.insert(done.request);
        }
    }
    dispatch(state)
}

#[cfg(test)]
mod tests {
    use pouw_consensus::MemState;
    use pouw_crypto::{Hash32, SigningKey};
    use pouw_provers::MockProver;
    use pouw_types::{
        Account, Amount, Block, ChainId, CircuitId, Nonce, ProofTx, TxBody, UsageCounter,
        encoded_len, sign_body, txid,
    };

    use super::*;
    use crate::mempool::{self, MempoolLimits};

    fn header(target: pouw_types::Target) -> BlockHeader {
        BlockHeader {
            version: pouw_types::U32::new(1),
            chain_id: pouw_types::U32::new(1),
            system_id: U64::new(0),
            height: U64::new(1),
            parent: BlockId::ZERO,
            timestamp: U64::new(1),
            miner: Address([9; 32]),
            tx_root: Hash32::ZERO,
            target,
            nonce: U64::new(0),
        }
    }

    fn easy_target() -> pouw_types::Target {
        let mut bytes = [0xff; 32];
        bytes[0] = 0x0f;
        pouw_types::Target(bytes)
    }

    fn params() -> ConsensusParams {
        let target = pouw_types::Target([0xff; 32]);
        ConsensusParams {
            chain_id: ChainId(1),
            initial_subsidy: Amount(50),
            halving_interval: 100,
            target_block_secs: 10,
            half_life_secs: 100,
            initial_target: target,
            pow_limit: target,
            max_future_secs: 300,
            fee_per_public_input: Amount(0),
            fee_per_witness_kib: Amount(0),
        }
    }

    fn pool() -> Mempool {
        mempool::new(MempoolLimits {
            max_bytes: 1 << 20,
            sender_slots: 64,
        })
    }

    fn signed(seed: u8, nonce: u64, fee: u64, kind: TxKind) -> SignedTx {
        let key = SigningKey::from_seed([seed; 32]);
        sign_body(
            &TxBody {
                chain_id: ChainId(1),
                sender: key.address(),
                nonce: Nonce(nonce),
                fee: Amount(fee),
                kind,
            },
            &key,
        )
    }

    fn transfer(seed: u8, nonce: u64, fee: u64) -> SignedTx {
        let kind = TxKind::Transfer {
            to: Address([2; 32]),
            amount: Amount(1),
        };
        signed(seed, nonce, fee, kind)
    }

    fn request(seed: u8, nonce: u64, fee: u64) -> SignedTx {
        let kind = TxKind::ProofRequest {
            circuit: CircuitId(TxId(Hash32([3; 32]))),
            public_inputs: vec![],
            witness: Box::from([]),
        };
        signed(seed, nonce, fee, kind)
    }

    fn add(pool: &mut Mempool, tx: SignedTx) -> TxId {
        mempool::insert(pool, txid(&tx), tx).unwrap()
    }

    /// Balance of every account the tests use, enough for any fee and amount of them.
    const RICH: u64 = 1 << 40;

    /// A state where the senders `0..=255` hold `RICH` at nonce 0, except the nonces and
    /// balances of `accounts` given as `(seed, nonce, balance)`.
    fn state_of(accounts: &[(u8, u64, u64)]) -> MemState {
        let mut state = MemState::default();
        for seed in 0..=u8::MAX {
            let address = SigningKey::from_seed([seed; 32]).address();
            let account = Account {
                balance: Amount(RICH),
                nonce: Nonce(0),
            };
            state.accounts.insert(address, account);
        }
        for (seed, nonce, balance) in accounts {
            let address = SigningKey::from_seed([*seed; 32]).address();
            let account = Account {
                balance: Amount(*balance),
                nonce: Nonce(*nonce),
            };
            state.accounts.insert(address, account);
        }
        state
    }

    fn state_at(nonces: &[(u8, u64)]) -> MemState {
        let accounts: Vec<(u8, u64, u64)> = nonces
            .iter()
            .map(|(seed, nonce)| (*seed, *nonce, RICH))
            .collect();
        state_of(&accounts)
    }

    fn fees(candidate: &Candidate<'_>) -> Vec<u64> {
        candidate.coin_txs.iter().map(|tx| tx.body.fee.0).collect()
    }

    fn pick<'p>(pool: &'p Mempool, state: &MemState) -> Candidate<'p> {
        take(pool, state, &PROTOCOL_CAPS)
    }

    fn take<'p>(pool: &'p Mempool, state: &MemState, caps: &BlockCaps) -> Candidate<'p> {
        let excluding = BTreeSet::new();
        let requests = Requests::Take {
            excluding: &excluding,
        };
        candidate(pool, state, caps, requests).unwrap()
    }

    fn fee_of_request(candidate: &Candidate<'_>) -> Amount {
        candidate.request.unwrap().1.body.fee
    }

    fn block_of(candidate: &Candidate<'_>) -> Block {
        Block {
            header: BlockHeader {
                version: pouw_types::U32::new(1),
                chain_id: pouw_types::U32::new(1),
                system_id: pouw_types::U64::new(0),
                height: pouw_types::U64::new(1),
                parent: pouw_types::BlockId::ZERO,
                timestamp: pouw_types::U64::new(1),
                miner: Address([9; 32]),
                tx_root: Hash32::ZERO,
                target: pouw_types::Target([0xff; 32]),
                nonce: pouw_types::U64::new(0),
            },
            txs: candidate.coin_txs.iter().map(|tx| (*tx).clone()).collect(),
            proof_txs: vec![ProofTx {
                request: candidate.request.unwrap().1.clone(),
                usage_counter: UsageCounter(0),
                proof: vec![0; MAX_PROOF_BYTES].into_boxed_slice(),
            }],
        }
    }

    #[test]
    fn a_sender_without_funds_is_not_selected() {
        let mut pool = pool();
        add(&mut pool, transfer(1, 0, 5));
        add(&mut pool, transfer(2, 0, 7));
        let state = state_of(&[(1, 0, 0)]);
        let chosen = pick(&pool, &state);
        assert_eq!(fees(&chosen), [7]);
    }

    #[test]
    fn the_cost_of_a_chain_is_summed_over_its_senders_balance() {
        let mut pool = pool();
        // Each transfer costs its amount 1 plus its fee 3.
        for nonce in 0..3 {
            add(&mut pool, transfer(1, nonce, 3));
        }
        let state = state_of(&[(1, 0, 9)]);
        let chosen = pick(&pool, &state);
        assert_eq!(chosen.coin_txs.len(), 2);
        assert_eq!(chosen.coin_txs[1].body.nonce, Nonce(1));
    }

    #[test]
    fn a_request_the_sender_cannot_pay_is_passed_over() {
        let mut pool = pool();
        add(&mut pool, request(1, 0, 50));
        add(&mut pool, request(2, 0, 10));
        let state = state_of(&[(1, 0, 49)]);
        let chosen = pick(&pool, &state);
        assert_eq!(fee_of_request(&chosen), Amount(10));
    }

    #[test]
    fn a_template_of_the_pool_applies_to_the_state() {
        // An unfunded sender, a sender with room for two of three transactions and a
        // funded one: whatever the pool holds, `apply_block` accepts the template.
        let mut pool = pool();
        add(&mut pool, transfer(1, 0, 5));
        for nonce in 0..3 {
            add(&mut pool, transfer(2, nonce, 3));
        }
        add(&mut pool, transfer(3, 0, 1));
        let state = state_of(&[(1, 0, 0), (2, 0, 9)]);
        let chosen = pick(&pool, &state);
        assert_eq!(chosen.coin_txs.len(), 3);
        let block = Block {
            header: header(easy_target()),
            txs: chosen.coin_txs.iter().map(|tx| (*tx).clone()).collect(),
            proof_txs: Vec::new(),
        };
        let ids: Vec<TxId> = block.txs.iter().map(txid).collect();
        pouw_consensus::apply_block(
            &params(),
            &Prover::from(MockProver::default()),
            &state,
            &block,
            &ids,
        )
        .unwrap();
    }

    #[test]
    fn coin_txs_are_taken_with_no_request_in_the_pool() {
        let mut pool = pool();
        let state = state_at(&[]);
        let none = pick(&pool, &state);
        assert!(none.request.is_none() && none.coin_txs.is_empty());
        add(&mut pool, transfer(1, 0, 5));
        let chosen = pick(&pool, &state);
        assert!(chosen.request.is_none());
        assert_eq!(fees(&chosen), [5]);
    }

    #[test]
    fn skipping_requests_takes_none_and_leaves_their_room_to_coin_txs() {
        let mut pool = pool();
        add(&mut pool, request(9, 0, 100));
        add(&mut pool, transfer(1, 0, 5));
        let chosen = candidate(&pool, &state_at(&[]), &PROTOCOL_CAPS, Requests::Skip).unwrap();
        assert!(chosen.request.is_none());
        assert_eq!(fees(&chosen), [5]);
        let caps = BlockCaps {
            max_bytes: BASE_BYTES + encoded_len(&transfer(1, 0, 5)),
            ..PROTOCOL_CAPS
        };
        let tight = candidate(&pool, &state_at(&[]), &caps, Requests::Skip).unwrap();
        assert_eq!(fees(&tight), [5]);
    }

    #[test]
    fn an_excluded_request_is_not_taken() {
        let mut pool = pool();
        let best = add(&mut pool, request(4, 0, 30));
        add(&mut pool, request(5, 0, 10));
        let excluding = BTreeSet::from([best]);
        let requests = Requests::Take {
            excluding: &excluding,
        };
        let chosen = candidate(&pool, &state_at(&[]), &PROTOCOL_CAPS, requests).unwrap();
        assert_eq!(fee_of_request(&chosen), Amount(10));
    }

    #[test]
    fn the_template_takes_the_best_paying_request_and_coin_txs_by_rate() {
        let mut pool = pool();
        for (seed, fee) in [(1, 5), (2, 9), (3, 7)] {
            add(&mut pool, transfer(seed, 0, fee));
        }
        for (seed, fee) in [(4, 20), (5, 30), (6, 10)] {
            add(&mut pool, request(seed, 0, fee));
        }
        let chosen = pick(&pool, &state_at(&[]));
        assert_eq!(fee_of_request(&chosen), Amount(30));
        let (id, request) = chosen.request.unwrap();
        assert_eq!(*id, txid(request));
        assert_eq!(fees(&chosen), [9, 7, 5]);
    }

    #[test]
    fn a_nonce_gap_keeps_the_later_transactions_out() {
        let mut pool = pool();
        add(&mut pool, request(9, 0, 1));
        add(&mut pool, transfer(1, 0, 5));
        add(&mut pool, transfer(1, 2, 500));
        add(&mut pool, transfer(2, 0, 4));
        add(&mut pool, transfer(2, 1, 3));
        let chosen = pick(&pool, &state_at(&[]));
        assert_eq!(fees(&chosen), [5, 4, 3]);
    }

    #[test]
    fn only_the_next_nonce_of_the_account_starts_a_chain() {
        let mut pool = pool();
        add(&mut pool, request(9, 0, 1));
        add(&mut pool, transfer(1, 0, 5));
        add(&mut pool, transfer(1, 2, 6));
        add(&mut pool, transfer(2, 3, 7));
        add(&mut pool, transfer(2, 4, 8));
        let state = state_at(&[(1, 1), (2, 3)]);
        let chosen = pick(&pool, &state);
        assert_eq!(fees(&chosen), [7, 8]);
    }

    #[test]
    fn a_well_paying_successor_waits_for_its_predecessor() {
        let mut pool = pool();
        add(&mut pool, request(9, 0, 1));
        add(&mut pool, transfer(1, 0, 1));
        add(&mut pool, transfer(1, 1, 100));
        add(&mut pool, transfer(2, 0, 50));
        let chosen = pick(&pool, &state_at(&[]));
        assert_eq!(fees(&chosen), [50, 1, 100]);
    }

    #[test]
    fn a_request_ends_the_chain_of_its_sender() {
        let mut pool = pool();
        add(&mut pool, transfer(1, 0, 3));
        add(&mut pool, request(1, 1, 50));
        add(&mut pool, transfer(1, 2, 99));
        add(&mut pool, request(2, 0, 10));
        add(&mut pool, transfer(3, 0, 4));
        let chosen = pick(&pool, &state_at(&[]));
        assert_eq!(fee_of_request(&chosen), Amount(50));
        assert_eq!(fees(&chosen), [4, 3]);
    }

    #[test]
    fn the_entry_cap_counts_the_proof() {
        let mut pool = pool();
        add(&mut pool, request(9, 0, 1));
        for seed in 1..=5 {
            add(&mut pool, transfer(seed, 0, u64::from(seed)));
        }
        let caps = BlockCaps {
            max_txs: 4,
            ..PROTOCOL_CAPS
        };
        let chosen = take(&pool, &state_at(&[]), &caps);
        assert_eq!(fees(&chosen), [5, 4, 3]);
    }

    #[test]
    fn the_byte_cap_is_the_encoded_size_of_the_block() {
        let mut pool = pool();
        add(&mut pool, request(9, 0, 1));
        for seed in 1..=4 {
            add(&mut pool, transfer(seed, 0, u64::from(seed)));
        }
        let state = state_at(&[]);
        let everything = pick(&pool, &state);
        let full = encoded_len(&block_of(&everything));
        assert_eq!(everything.coin_txs.len(), 4);
        assert!(full <= MAX_BLOCK_BYTES);
        let tight = BlockCaps {
            max_bytes: full,
            ..PROTOCOL_CAPS
        };
        let fits = take(&pool, &state, &tight);
        assert_eq!(fits.coin_txs.len(), 4);
        let short = BlockCaps {
            max_bytes: full - 1,
            ..PROTOCOL_CAPS
        };
        let less = take(&pool, &state, &short);
        assert_eq!(fees(&less), [4, 3, 2]);
        assert!(encoded_len(&block_of(&less)) <= short.max_bytes);
    }

    #[test]
    fn caps_below_the_framing_leave_no_candidate() {
        let mut pool = pool();
        add(&mut pool, request(9, 0, 1));
        let caps = BlockCaps {
            max_bytes: BASE_BYTES + PROOF_OVERHEAD_BYTES - 1,
            ..PROTOCOL_CAPS
        };
        let chosen = take(&pool, &state_at(&[]), &caps);
        assert!(chosen.request.is_none() && chosen.coin_txs.is_empty());
    }

    #[test]
    fn verify_work_reports_the_pow_verdict_and_returns_the_block() {
        let params = params();
        let mut block = pouw_types::Block {
            header: pouw_types::BlockHeader {
                version: pouw_types::U32::new(1),
                chain_id: pouw_types::U32::new(1),
                system_id: pouw_types::U64::new(0),
                height: pouw_types::U64::new(1),
                parent: pouw_types::BlockId::ZERO,
                timestamp: pouw_types::U64::new(1),
                miner: pouw_crypto::Address([9; 32]),
                tx_root: Hash32::ZERO,
                target: pouw_types::Target([0; 32]),
                nonce: pouw_types::U64::new(0),
            },
            txs: vec![],
            proof_txs: vec![],
        };
        let checked = |block: &pouw_types::Block| CheckedBlock {
            bytes: borsh::to_vec(block).unwrap(),
            block: block.clone(),
            txids: vec![],
        };
        let unmined = verify_work(&params, checked(&block));
        assert!(unmined.verdict.is_err());
        assert_eq!(unmined.block.block, block);
        block.header.target = params.pow_limit;
        let easy = verify_work(&params, checked(&block));
        assert_eq!(easy.verdict, Ok(()));
    }

    #[test]
    fn a_search_returns_the_first_nonce_of_its_range_that_meets_the_target() {
        let job = SearchJob {
            key: 3,
            header: header(easy_target()),
            start: 1_000,
            count: 4_096,
        };
        let done = search_nonce(&job);
        let PowNonce(nonce) = done.found.expect("an easy target is met within the range");
        assert!((1_000..5_096).contains(&nonce));
        assert_eq!(done.key, 3);
        assert_eq!(done.next_start, 5_096);
        let mut sealed = job.header;
        for before in 1_000..nonce {
            sealed.nonce = U64::new(before);
            assert!(block_id(&sealed).0.0 > sealed.target.0);
        }
        sealed.nonce = U64::new(nonce);
        assert!(block_id(&sealed).0.0 <= sealed.target.0);
    }

    #[test]
    fn a_search_that_finds_nothing_names_where_the_next_range_starts() {
        let job = SearchJob {
            key: 1,
            header: header(pouw_types::Target([0; 32])),
            start: 10,
            count: 100,
        };
        let done = search_nonce(&job);
        assert_eq!((done.found, done.next_start), (None, 110));
    }

    #[test]
    fn a_range_that_reaches_the_end_of_the_nonces_is_exhausted() {
        let job = SearchJob {
            key: 1,
            header: header(pouw_types::Target([0; 32])),
            start: u64::MAX - 5,
            count: SEARCH_BATCH,
        };
        assert_eq!(search_nonce(&job).next_start, u64::MAX);
    }

    #[test]
    fn the_worker_runs_a_search_and_a_proof_and_answers_in_order() {
        let prover = Prover::from(MockProver::default());
        let keys = prover.setup(b"circuit").unwrap();
        let proof = ProofJob {
            request: TxId(Hash32([4; 32])),
            circuit: Box::from(*b"circuit"),
            eta: Hash32([1; 32]),
            mask: Hash32([2; 32]),
            client_inputs: vec![],
            witness: Box::from([]),
        };
        let search = SearchJob {
            key: 8,
            header: header(easy_target()),
            start: 0,
            count: 4_096,
        };
        let (jobs, inbox) = mpsc::channel(2);
        let (work, mut answers) = mpsc::channel(2);
        jobs.try_send(WorkJob::SearchNonce(Box::new(search.clone())))
            .unwrap();
        jobs.try_send(WorkJob::Prove(Box::new(proof.clone())))
            .unwrap();
        drop(jobs);
        run_work_worker(&prover, &params(), inbox, &work).unwrap();
        assert_eq!(
            answers.try_recv().unwrap(),
            WorkDone::Nonce(search_nonce(&search))
        );
        let Ok(WorkDone::Proof(done)) = answers.try_recv() else {
            panic!("no proof came back");
        };
        assert_eq!(done, prove(&prover, &proof));
        let statement = Statement::new(&proof.eta, &proof.mask, &[]);
        let made = done.proof.unwrap();
        assert!(
            prover
                .verify(&keys.verifying_key, &statement, &made)
                .unwrap()
        );
    }
}
