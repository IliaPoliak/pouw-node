//! The chain pipeline: what happens to a transaction or a block that arrives from a
//! peer, the API or the miner, in the order of `docs/FOR-ILIA.md`. Every function
//! takes the parts of the node state it reads or changes and returns a typed outcome;
//! the loop turns the outcome into a gossip verdict or an API answer.

#[cfg(test)]
use std::cell::Cell;
use std::time::Instant;

use pouw_api::event::{
    BlockAccepted, BlockOrphaned, BlockRejected, EventKind, TxReceived, TxRejected,
};
use pouw_consensus::{
    Anchor, BlockError, ChainTip, Change, ConsensusParams, HeaderContext, InvalidBlock, InvalidTx,
    StateDiff, StateError, apply_block, better, check_header, median_time_past, next_target,
    timestamp::MTP_WINDOW,
};
use pouw_provers::ProverError;
use pouw_types::{
    Account, Block, BlockHeader, BlockId, ChainSpec, Height, Nonce, SystemId, Target, Timestamp,
    TxId, block_id,
};
use thiserror::Error;
use tracing::{debug, warn};

use crate::{
    events::{self, EventLog, SeqExhausted},
    mempool::{self, Mempool, MempoolError},
    metrics::Metrics,
    p2p::Acceptance,
    precheck::{CheckedBlock, CheckedTx},
    store::{
        self, Reader, Store, StoreError,
        schema::{IndexEntry, Status},
    },
};

/// The node failed while it handled a transaction or a block, which is no verdict on
/// the transaction or the block.
#[derive(Debug, Error)]
pub enum ChainFault {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Events(#[from] SeqExhausted),
    /// The state could not be read while a block was applied.
    #[error(transparent)]
    State(#[from] StateError),
    /// The prover failed for a reason other than the proof.
    #[error("prover failure: {0}")]
    Prover(ProverError),
}

/// What the state transition of a block means for the node: only an invalid block is
/// held against a peer.
fn fault_or_invalid(error: BlockError) -> Result<InvalidBlock, ChainFault> {
    match error {
        BlockError::Invalid(invalid) => Ok(invalid),
        BlockError::State(state) => Err(ChainFault::State(state)),
        BlockError::Prover(prover) => Err(ChainFault::Prover(prover)),
    }
}

/// What became of a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum TxOutcome {
    /// It is pending in the mempool.
    Pooled(TxId),
    /// It breaks a rule.
    Invalid(InvalidTx),
    /// It may be valid, but the mempool does not take it.
    Refused(MempoolError),
}

/// What became of a block.
#[derive(Debug)]
#[must_use]
pub enum BlockOutcome {
    /// It extends the tip and is the new tip.
    Connected(ChainTip),
    /// It is stored already.
    Known,
    /// Its parent is not stored, so it cannot be checked yet.
    UnknownParent,
    /// It is on a side branch with no more cumulative work than the tip, so it is
    /// stored and the tip stays.
    SideBranch(BlockId),
    /// It ends a side branch with more cumulative work than the tip, so the
    /// chain switched to that branch.
    Reorganized(ChainTip),
    /// It breaks a rule.
    Invalid(InvalidBlock),
    /// It is valid on its own, but its parent or an ancestor failed, so it is stored
    /// as failed and is never connected.
    ParentFailed(BlockId),
}

/// Why the node cannot start on its store and chain spec.
#[derive(Debug, Error)]
pub enum GenesisError {
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The store holds a chain whose genesis is not the one of the spec.
    #[error(
        "the store belongs to another chain: its genesis is {stored:?}, the spec has {expected}"
    )]
    ForeignChain {
        /// The canonical block at height 0 of the store.
        stored: Option<BlockId>,
        /// The genesis id of the spec.
        expected: BlockId,
    },
}

/// The tip the node starts from. An empty store receives `genesis`, the block of
/// `pouw_types::genesis_block`, and `spec.allocations` become accounts with nonce 0 in
/// the atomic write that connects it. A store with blocks must have `genesis` at height 0, else the
/// node would run one chain on the state of another.
pub fn genesis(
    store: &mut Store,
    spec: &ChainSpec,
    genesis: &Block,
) -> Result<ChainTip, GenesisError> {
    let id = block_id(&genesis.header);
    let (tip, stored) = {
        let reader = store::read(store)?;
        (
            store::tip(&reader)?,
            store::canonical_id(&reader, Height(0))?,
        )
    };
    if let Some(tip) = tip {
        return if stored == Some(id) {
            Ok(tip)
        } else {
            Err(GenesisError::ForeignChain {
                stored,
                expected: id,
            })
        };
    }
    let accounts = spec
        .allocations
        .iter()
        .map(|allocation| {
            let account = Account {
                balance: allocation.amount,
                nonce: Nonce(0),
            };
            (
                allocation.address,
                Change {
                    before: None,
                    after: Some(account),
                },
            )
        })
        .collect();
    let bytes = borsh::to_vec(genesis).map_err(StoreError::Encode)?;
    let mut txids = Vec::new();
    genesis.txids_into(&mut txids);
    store::put_header(store, &id, &genesis.header)?;
    store::put_body(store, &id, &bytes)?;
    store::mark_work_valid(store, &id)?;
    let diff = StateDiff {
        accounts,
        ..StateDiff::default()
    };
    Ok(store::connect_block(store, &id, &txids, &diff)?)
}

pub fn tx_acceptance(outcome: &TxOutcome) -> Acceptance {
    match outcome {
        TxOutcome::Pooled(_) => Acceptance::Accept,
        TxOutcome::Invalid(_) => Acceptance::Reject,
        TxOutcome::Refused(_) => Acceptance::Ignore,
    }
}

/// Pools a transaction that passed the precheck. The stateful admission check against
/// the tip state is pouw-node#66; until it exists a transaction passes on the stateless
/// rules.
pub fn receive_tx(
    mempool: &mut Mempool,
    log: &mut EventLog,
    checked: CheckedTx,
) -> Result<TxOutcome, SeqExhausted> {
    let CheckedTx { tx, txid } = checked;
    let (tx_kind, sender, fee) = (tx.body.kind.name(), tx.body.sender, tx.body.fee);
    match mempool::insert(mempool, txid, tx) {
        Ok(id) => {
            let kind = EventKind::TxReceived(TxReceived {
                txid: id,
                tx_kind: tx_kind.to_owned(),
                sender,
                fee,
            });
            events::emit(log, kind)?;
            Ok(TxOutcome::Pooled(id))
        }
        Err(refused) => {
            debug!(%refused, "transaction not pooled");
            Ok(TxOutcome::Refused(refused))
        }
    }
}

/// Records a transaction that failed the precheck on the API path, where the loop runs
/// the precheck itself.
pub fn reject_tx(log: &mut EventLog, invalid: InvalidTx) -> Result<TxOutcome, SeqExhausted> {
    let kind = EventKind::TxRejected(TxRejected {
        txid: None,
        reason_code: invalid.reason_code().to_owned(),
        message: invalid.to_string(),
    });
    events::emit(log, kind)?;
    Ok(TxOutcome::Invalid(invalid))
}

/// Connects a block that passed the precheck: checks it against its stored parent,
/// then stores its header, its received bytes and its verified work, in that order, and
/// connects it when it extends the tip. A block on a side branch is stored, and the
/// chain switches to its branch when the branch has more cumulative work than the tip.
/// A block whose header fails the check is not stored. A block of a failed branch is
/// stored as failed and answers [`BlockOutcome::ParentFailed`]. A block the state
/// transition rejects (`pouw_consensus::apply_block`) is stored as failed, recorded as
/// `block_rejected` and answers [`BlockOutcome::Invalid`], or
/// [`BlockOutcome::ParentFailed`] when it is an ancestor of the received block on a
/// branch that would have become the chain. `now` is the clock of the node, read once
/// by the caller, for the timestamp rule.
pub fn receive_block(
    store: &mut Store,
    mempool: &mut Mempool,
    log: &mut EventLog,
    metrics: &mut Metrics,
    params: &ConsensusParams,
    now: Timestamp,
    checked: &CheckedBlock,
) -> Result<BlockOutcome, ChainFault> {
    let block = &checked.block;
    let started = Instant::now();
    let id = block_id(&block.header);
    let extends_tip = {
        let reader = store::read(store)?;
        if let Some(known) = store::index(&reader, &id)?
            && known.status.contains(Status::BODY_STORED)
        {
            return Ok(BlockOutcome::Known);
        }
        let Some(verdict) = check_against_parent(&reader, params, now, &block.header)? else {
            debug!(%id, "block with an unknown parent");
            return Ok(BlockOutcome::UnknownParent);
        };
        metrics.verifications = metrics.verifications.saturating_add(1);
        metrics.verification_time = metrics.verification_time.saturating_add(started.elapsed());
        if let Err(invalid) = verdict {
            emit_rejected(log, &id, &block.header, &invalid)?;
            return Ok(BlockOutcome::Invalid(invalid));
        }
        store::tip(&reader)?.is_some_and(|tip| tip.id == block.header.parent)
    };
    let entry = store::put_header(store, &id, &block.header)?;
    store::put_body(store, &id, &checked.bytes)?;
    store::mark_work_valid(store, &id)?;
    if entry.status.contains(Status::FAILED) {
        warn!(%id, "block of a failed branch");
        return Ok(BlockOutcome::ParentFailed(id));
    }
    if extends_tip {
        return Ok(
            match connect_stored(store, mempool, log, params, block, &checked.txids, &id)? {
                Connect::Connected(tip) => {
                    record_block(store, metrics, block)?;
                    BlockOutcome::Connected(tip)
                }
                Connect::Rejected(invalid) => BlockOutcome::Invalid(invalid),
            },
        );
    }
    side_branch(store, mempool, log, params, &id)
}

/// Counts a block that extended the tip: the block, its proofs and the seconds since its
/// parent. A block connected by a reorganization is not counted.
fn record_block(store: &Store, metrics: &mut Metrics, block: &Block) -> Result<(), ChainFault> {
    let reader = store::read(store)?;
    let parent = store::header(&reader, &block.header.parent)?.map(|h| h.timestamp.get());
    let secs = parent.map_or(0, |parent| {
        block.header.timestamp.get().saturating_sub(parent)
    });
    metrics.blocks_connected = metrics.blocks_connected.saturating_add(1);
    metrics.block_time_secs = metrics.block_time_secs.saturating_add(secs);
    let proofs = u64::try_from(block.proof_txs.len()).unwrap_or(u64::MAX);
    metrics.block_proofs = metrics.block_proofs.saturating_add(proofs);
    Ok(())
}

fn emit_rejected(
    log: &mut EventLog,
    id: &BlockId,
    header: &BlockHeader,
    invalid: &InvalidBlock,
) -> Result<(), SeqExhausted> {
    let kind = EventKind::BlockRejected(BlockRejected {
        id: *id,
        height: Some(Height(header.height.get())),
        reason_code: invalid.reason_code().to_owned(),
    });
    events::emit(log, kind)?;
    Ok(())
}

/// What became of an announced header.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum HeaderOutcome {
    /// Its id is indexed already.
    Known,
    /// Its parent is not stored, so it cannot be checked yet and is not stored.
    UnknownParent,
    /// It breaks a rule of [`check_header`] and is not stored.
    Invalid(InvalidBlock),
    /// It passed [`check_header`] and is indexed without its body.
    Stored(IndexEntry),
}

/// Checks the header `header` of block `id` against its stored parent with
/// [`check_header`] (version, chain id, height, target of `next_target`, timestamp) and
/// indexes it with [`store::put_header`] when it passes, the step of an announced or
/// synced header before its body is fetched. `now` is the clock of the node, read once by
/// the caller. A header whose parent is not stored is never indexed, so no peer can add
/// a second root next to the genesis.
pub fn receive_header(
    store: &mut Store,
    params: &ConsensusParams,
    now: Timestamp,
    id: &BlockId,
    header: &BlockHeader,
) -> Result<HeaderOutcome, StoreError> {
    {
        let reader = store::read(store)?;
        if store::index(&reader, id)?.is_some() {
            return Ok(HeaderOutcome::Known);
        }
        match check_against_parent(&reader, params, now, header)? {
            None => return Ok(HeaderOutcome::UnknownParent),
            Some(Err(invalid)) => return Ok(HeaderOutcome::Invalid(invalid)),
            Some(Ok(())) => {}
        }
    }
    Ok(HeaderOutcome::Stored(store::put_header(store, id, header)?))
}

/// The verdict of [`check_header`] on `header` against its stored parent and the chain
/// behind it, `None` when the parent is not stored.
fn check_against_parent(
    reader: &Reader<'_>,
    params: &ConsensusParams,
    now: Timestamp,
    header: &BlockHeader,
) -> Result<Option<Result<(), InvalidBlock>>, StoreError> {
    let Some(parent) = store::header(reader, &header.parent)? else {
        return Ok(None);
    };
    let (anchor, mtp) = ancestry(reader, params, &header.parent, parent)?;
    let context = HeaderContext {
        params,
        anchor: &anchor,
        mtp,
        now,
    };
    Ok(Some(check_header(&context, parent, header)))
}

/// What a child of a stored block must carry in its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildRules {
    /// The header of the parent.
    pub parent: BlockHeader,
    /// The `target` of the child: [`next_target`] of the parent, with the anchor
    /// `check_against_parent` reads.
    pub target: Target,
    /// The median time past of the chain that ends in the parent: the child's timestamp
    /// is above it.
    pub mtp: Timestamp,
}

/// The target and the timestamp floor of a child of the stored block `parent_id`, from
/// the same `ancestry` that `check_against_parent` reads, so a header built from them
/// passes [`check_header`]. `None` when the parent is not stored.
pub fn child_rules(
    reader: &Reader<'_>,
    params: &ConsensusParams,
    parent_id: &BlockId,
) -> Result<Option<ChildRules>, StoreError> {
    let Some(parent) = store::header(reader, parent_id)? else {
        return Ok(None);
    };
    let (anchor, mtp) = ancestry(reader, params, parent_id, parent)?;
    let target = next_target(params, SystemId(0), &anchor, parent)
        .map_err(|error| StoreError::Corrupt(format!("no target after {parent_id}: {error}")))?;
    Ok(Some(ChildRules {
        parent: *parent,
        target,
        mtp,
    }))
}

/// The anchor of the target rule and the median time past of the chain that ends in
/// `parent`, whose id is `parent_id`. Both are read by walking parent links from
/// `parent`: the last [`MTP_WINDOW`] timestamps, then on to block 1 when the walk has
/// not met it. The walk jumps to the canonical block 1 as soon as the block index marks
/// it [`Status::CONNECTED`], so it is as long as the side branch plus [`MTP_WINDOW`].
fn ancestry(
    reader: &Reader<'_>,
    params: &ConsensusParams,
    parent_id: &BlockId,
    parent: &BlockHeader,
) -> Result<(Anchor, Timestamp), StoreError> {
    if parent.height.get() == 0 {
        let anchor = Anchor::first_block(params, parent);
        return Ok((
            anchor,
            median_time_past(&[Timestamp(parent.timestamp.get())]),
        ));
    }
    let mut times = Vec::with_capacity(MTP_WINDOW);
    let mut first = None;
    let (mut id, mut header) = (*parent_id, *parent);
    loop {
        if times.len() < MTP_WINDOW {
            times.push(Timestamp(header.timestamp.get()));
        }
        let height = Height(header.height.get());
        if height.0 == 1 {
            first = Some(header);
        }
        if height.0 == 0 {
            break;
        }
        if times.len() >= MTP_WINDOW {
            if first.is_some() {
                break;
            }
            let connected = store::index(reader, &id)?
                .is_some_and(|entry| entry.status.contains(Status::CONNECTED));
            if connected {
                let first_id = store::canonical_id(reader, Height(1))?
                    .ok_or_else(|| StoreError::Corrupt("no canonical block 1".into()))?;
                first = store::header(reader, &first_id)?.copied();
                break;
            }
        }
        id = header.parent;
        header = *store::header(reader, &id)?.ok_or(StoreError::UnknownBlock(id))?;
    }
    let first = first.ok_or_else(|| StoreError::Corrupt("the chain has no block 1".into()))?;
    let genesis =
        *store::header(reader, &first.parent)?.ok_or(StoreError::UnknownBlock(first.parent))?;
    times.reverse();
    Ok((
        Anchor::from_block(&first, &genesis),
        median_time_past(&times),
    ))
}

/// The blocks of a side branch and the tip the chain has when it follows them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Branch {
    /// The canonical block the branch grows from.
    pub fork: BlockId,
    /// The blocks above `fork`, oldest first.
    pub blocks: Vec<BlockId>,
    /// The tip after the last block of `blocks`.
    pub tip: ChainTip,
    /// The oldest block of `blocks` the index marks [`Status::FAILED`]. While it is set
    /// the branch is never connected.
    pub failed: Option<BlockId>,
}

/// Finds where the stored block `id` leaves the canonical chain: the walk by parent
/// links stops at the first block the index marks [`Status::CONNECTED`]. The cumulative
/// work of the branch tip is the one in the index, the one fork choice compares. A
/// block failed after its descendants were stored is met on the walk and reported in
/// [`Branch::failed`].
pub fn find_branch(reader: &Reader<'_>, id: &BlockId) -> Result<Branch, StoreError> {
    let mut blocks = Vec::new();
    let mut failed = None;
    let mut current = *id;
    let fork = loop {
        let entry = store::index(reader, &current)?.ok_or(StoreError::UnknownBlock(current))?;
        if entry.status.contains(Status::CONNECTED) {
            break current;
        }
        if entry.status.contains(Status::FAILED) {
            failed = Some(current);
        }
        blocks.push(current);
        let header = store::header(reader, &current)?.ok_or(StoreError::UnknownBlock(current))?;
        current = header.parent;
    };
    let entry = store::index(reader, id)?.ok_or(StoreError::UnknownBlock(*id))?;
    blocks.reverse();
    Ok(Branch {
        fork,
        blocks,
        tip: ChainTip {
            id: *id,
            height: entry.height(),
            cumulative_work: entry.work(),
        },
        failed,
    })
}

/// Switches to the branch ending in the stored block `id` when it beats the tip. A
/// branch through a failed block is never followed: the failed block's stored
/// descendants on it, `id` included, are marked [`Status::FAILED`].
fn side_branch(
    store: &mut Store,
    mempool: &mut Mempool,
    log: &mut EventLog,
    params: &ConsensusParams,
    id: &BlockId,
) -> Result<BlockOutcome, ChainFault> {
    let (tip, branch) = {
        let reader = store::read(store)?;
        let Some(tip) = store::tip(&reader)? else {
            return Ok(BlockOutcome::SideBranch(*id));
        };
        let branch = find_branch(&reader, id)?;
        (tip, branch)
    };
    if let Some(failed) = branch.failed {
        warn!(%id, %failed, "block of a branch through a failed block");
        for id in branch.blocks.iter().skip_while(|id| **id != failed) {
            store::mark_failed(store, id)?;
        }
        return Ok(BlockOutcome::ParentFailed(*id));
    }
    if !better(&tip, &branch.tip) {
        warn!(%id, "a side branch with no more work than the tip is stored");
        return Ok(BlockOutcome::SideBranch(*id));
    }
    Ok(match reorg(store, mempool, log, params, &tip, &branch)? {
        Reorg::Switched(tip) => BlockOutcome::Reorganized(tip),
        Reorg::Rejected { block, invalid } if block == *id => BlockOutcome::Invalid(invalid),
        Reorg::Rejected { block, .. } => {
            warn!(%id, %block, "block of a branch through a rejected block");
            BlockOutcome::ParentFailed(*id)
        }
    })
}

/// What became of a switch to a branch.
#[derive(Debug)]
#[must_use]
pub enum Reorg {
    /// The chain follows the branch and this is its tip.
    Switched(ChainTip),
    /// `block` of the branch broke a rule while it connected. It and the blocks above it
    /// are marked [`Status::FAILED`], and the chain is the valid one with the most work
    /// of the old tip and the part of the branch below `block`.
    Rejected {
        block: BlockId,
        invalid: InvalidBlock,
    },
}

/// Disconnects the canonical blocks above `branch.fork`, returns their transactions
/// to the mempool, then connects `branch.blocks`, each through `connect_stored`.
/// Fork choice by cumulative work is [`better`], pouw-node#78. When a block of the
/// branch is rejected, the branch from that block up is marked failed and the chain
/// goes back to the old tip `tip` unless the part of the branch below the block has
/// more work, so the node is on a valid chain. An error in the middle leaves the chain
/// at the last block that was disconnected or connected.
pub fn reorg(
    store: &mut Store,
    mempool: &mut Mempool,
    log: &mut EventLog,
    params: &ConsensusParams,
    tip: &ChainTip,
    branch: &Branch,
) -> Result<Reorg, ChainFault> {
    let mut current = *tip;
    while current.id != branch.fork {
        let orphaned = load_block(store, &current.id)?;
        let kind = EventKind::BlockOrphaned(BlockOrphaned {
            id: current.id,
            height: current.height,
        });
        current = store::disconnect_tip(store, &orphaned.txids)?;
        events::emit(log, kind)?;
        let Block { txs, proof_txs, .. } = orphaned.block;
        let requests = proof_txs.into_iter().map(|proof| proof.request);
        for (id, tx) in orphaned
            .txids
            .into_iter()
            .zip(txs.into_iter().chain(requests))
        {
            if let Err(refused) = mempool::insert(mempool, id, tx) {
                debug!(%refused, "transaction of an orphaned block not pooled");
            }
        }
    }
    for id in &branch.blocks {
        let stored = load_block(store, id)?;
        match connect_stored(
            store,
            mempool,
            log,
            params,
            &stored.block,
            &stored.txids,
            id,
        )? {
            Connect::Connected(connected) => current = connected,
            Connect::Rejected(invalid) => {
                warn!(%id, %invalid, "a block of the new branch is rejected");
                for failed in branch.blocks.iter().skip_while(|failed| *failed != id) {
                    store::mark_failed(store, failed)?;
                }
                if better(&current, tip) {
                    return_to(store, mempool, log, params, &current, tip)?;
                }
                return Ok(Reorg::Rejected {
                    block: *id,
                    invalid,
                });
            }
        }
    }
    Ok(Reorg::Switched(current))
}

/// Switches the chain from `from` back to the tip `old`, which was canonical before
/// the switch that failed, with the same [`reorg`].
fn return_to(
    store: &mut Store,
    mempool: &mut Mempool,
    log: &mut EventLog,
    params: &ConsensusParams,
    from: &ChainTip,
    old: &ChainTip,
) -> Result<(), ChainFault> {
    let branch = find_branch(&store::read(store)?, &old.id)?;
    match reorg(store, mempool, log, params, from, &branch)? {
        Reorg::Switched(_) => Ok(()),
        Reorg::Rejected { block, invalid } => Err(StoreError::Corrupt(format!(
            "block {block} was canonical and is now rejected: {invalid}"
        ))
        .into()),
    }
}

/// A stored block decoded for a reorganization, with its txids.
struct Loaded {
    block: Block,
    txids: Vec<TxId>,
}

/// Decodes the stored block `id` once and computes its txids once.
fn load_block(store: &Store, id: &BlockId) -> Result<Loaded, StoreError> {
    let reader = store::read(store)?;
    let stored = store::block(&reader, id)?.ok_or(StoreError::UnknownBlock(*id))?;
    let block = store::decode(&stored)?;
    let mut txids = Vec::new();
    block.txids_into(&mut txids);
    Ok(Loaded { block, txids })
}

/// What became of a stored block that was applied to the tip.
enum Connect {
    Connected(ChainTip),
    /// The state transition rejected it. It is marked [`Status::FAILED`] and recorded as
    /// `block_rejected`, the same as a block that fails a stateless rule.
    Rejected(InvalidBlock),
}

/// Applies the stored `block`, whose ids are `txids`, to the tip state with
/// [`apply_block`] and connects it, drops its transactions from the mempool and records
/// it. A block the transition rejects is marked failed and recorded as rejected.
fn connect_stored(
    store: &mut Store,
    mempool: &mut Mempool,
    log: &mut EventLog,
    params: &ConsensusParams,
    block: &Block,
    txids: &[TxId],
    id: &BlockId,
) -> Result<Connect, ChainFault> {
    let transition = transition(&store::read(store)?, params, block, txids, id);
    let diff = match transition {
        Ok(diff) => diff,
        Err(error) => {
            let invalid = fault_or_invalid(error)?;
            store::mark_failed(store, id)?;
            emit_rejected(log, id, &block.header, &invalid)?;
            return Ok(Connect::Rejected(invalid));
        }
    };
    if diff == StateDiff::default() {
        warn!(
            height = block.header.height.get(),
            "pouw-node#77: no state transition, the block leaves the state unchanged"
        );
    }
    let tip = store::connect_block(store, id, txids, &diff)?;
    let requests = block.proof_txs.iter().map(|proof| &proof.request);
    for tx in block.txs.iter().chain(requests) {
        mempool::remove_through(mempool, &tx.body.sender, tx.body.nonce);
    }
    let kind = EventKind::BlockAccepted(BlockAccepted {
        id: *id,
        height: tip.height,
        miner: block.header.miner,
        tx_count: mempool::count(block.txs.len()),
        proof_count: mempool::count(block.proof_txs.len()),
    });
    events::emit(log, kind)?;
    Ok(Connect::Connected(tip))
}

#[cfg(not(test))]
fn transition(
    reader: &Reader<'_>,
    params: &ConsensusParams,
    block: &Block,
    txids: &[TxId],
    _id: &BlockId,
) -> Result<StateDiff, BlockError> {
    apply_block(params, reader, block, txids)
}

#[cfg(test)]
fn transition(
    reader: &Reader<'_>,
    params: &ConsensusParams,
    block: &Block,
    txids: &[TxId],
    id: &BlockId,
) -> Result<StateDiff, BlockError> {
    if REJECTED.with(Cell::get) == Some(*id) {
        return Err(InvalidBlock::BadParent.into());
    }
    apply_block(params, reader, block, txids)
}

#[cfg(test)]
thread_local! {
    static REJECTED: Cell<Option<BlockId>> = const { Cell::new(None) };
}

/// Makes the state transition of block `id` answer [`InvalidBlock::BadParent`], so a
/// test can drive the invalid-block path before the transition has any rule of its own.
#[cfg(test)]
pub(crate) fn reject_on_connect(id: Option<BlockId>) {
    REJECTED.with(|rejected| rejected.set(id));
}

#[cfg(test)]
mod tests;
