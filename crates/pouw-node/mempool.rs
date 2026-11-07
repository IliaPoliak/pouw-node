//! Pending transactions. The pool holds what the caller already accepted and answers
//! the queries of the miner, the API and the events; admission rules are in
//! `pouw_consensus` and run before [`insert`].
//!
//! # Indexes
//!
//! `txs` owns every pending transaction. Two indexes point into it and [`insert`] and
//! [`remove`] keep all three in step:
//! - `by_fee`: `(FeeRate, TxId)` in ascending order, so the first entry is the one to
//!   evict when the pool is full and the last is the best paying.
//! - `senders`: per sender the pending transactions by nonce. A transaction is
//!   selectable for a block only when its nonce is the next nonce of the account at the
//!   tip or follows a selected one of the same sender, see `miner::candidate`.
//!
//! # Policies
//!
//! - Replacement: a transaction with the sender and nonce of a pending one replaces it
//!   when its fee is strictly higher, otherwise it is refused with
//!   [`MempoolError::Underpriced`]. The replaced transaction leaves at once and its bytes
//!   count as free for the admission of the new one. There is no minimum bump, so a
//!   sender can churn the pool with fee steps of one unit.
//! - Eviction: when the bytes do not fit, the transactions with the lowest fee rate
//!   leave first, but only those whose rate is strictly below the new one. A new
//!   transaction that cannot make room that way is refused with [`MempoolError::Full`]
//!   and nothing is evicted. An evicted transaction can leave a higher nonce of the
//!   same sender without its predecessor, which stays pending and unselectable until
//!   the predecessor is pooled again or the chain passes its nonce ([`remove_through`]).
//! - Sender slots bound how many transactions one sender queues, replacements keep
//!   their slot.

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
};

use pouw_api::{event::MempoolSnapshot, view::MempoolView};
use pouw_crypto::Address;
use pouw_types::{Amount, CircuitId, FastMap, Nonce, SignedTx, TxBody, TxId, TxKind, encoded_len};
use thiserror::Error;

/// Most bytes of `verifying_key` and `circuit` together that the node relays and
/// pools, a policy stricter than the consensus limit `MAX_CIRCUIT_BYTES`.
pub const MAX_RELAY_CIRCUIT_BYTES: usize = 1 << 20;

/// Most transactions the pool holds, so every count of the pool fits the `u32` of the
/// API views.
pub const MAX_PENDING_TXS: u32 = u32::MAX;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MempoolError {
    #[error("a circuit of {found} bytes is over the relay cap of {limit}")]
    OverRelayCap { found: usize, limit: usize },
    #[error("{0} is already pending")]
    Duplicate(TxId),
    #[error("the mempool holds its limit of {max_bytes} bytes")]
    Full { max_bytes: usize },
    #[error("{sender:?} already has its {slots} pending transactions")]
    SenderFull { sender: Address, slots: usize },
    #[error("the mempool holds its limit of {limit} transactions")]
    TooMany { limit: u32 },
    #[error("a transaction of {bytes} bytes has no fee rate")]
    Oversized { bytes: usize },
    #[error("{existing} with the same nonce pays {fee:?}, a replacement must pay more")]
    Underpriced { existing: TxId, fee: Amount },
}

/// What the pool may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolLimits {
    /// Most borsh bytes of all pending transactions together.
    pub max_bytes: usize,
    /// Most pending transactions of one sender.
    pub sender_slots: usize,
}

/// Fee per byte of a transaction, kept as the pair (`fee`, `size`) and compared by
/// cross-multiplication in `u128`: `a < b` when `a.fee * b.size < b.fee * a.size`.
/// A division would truncate and make different rates equal, and a fixed-point scale
/// would have to pick a precision. The product of a `u64` and a `u32` is below 2^96,
/// so the comparison is exact and the saturating multiplication never saturates. Two
/// pairs of the same ratio, such as 1/2 and 2/4, are equal.
#[derive(Debug, Clone, Copy)]
pub struct FeeRate {
    pub fee: Amount,
    /// Borsh bytes of the transaction.
    pub size: u32,
}

fn cross(fee: Amount, size: u32) -> u128 {
    u128::from(fee.0).saturating_mul(u128::from(size))
}

impl Ord for FeeRate {
    fn cmp(&self, other: &Self) -> Ordering {
        cross(self.fee, other.size).cmp(&cross(other.fee, self.size))
    }
}

impl PartialOrd for FeeRate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for FeeRate {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for FeeRate {}

#[derive(Debug, Clone)]
pub struct Pending {
    pub tx: SignedTx,
    pub bytes: usize,
    pub rate: FeeRate,
}

/// The pending transactions, by txid. `bytes`, `by_fee` and `senders` describe what
/// `txs` holds; [`insert`] and [`remove`] keep them in step.
#[derive(Debug, Clone)]
pub struct Mempool {
    pub limits: MempoolLimits,
    /// Borsh bytes of all pending transactions.
    pub bytes: usize,
    pub txs: FastMap<TxId, Pending>,
    /// Every pending transaction by ascending fee rate, ties by txid.
    pub by_fee: BTreeSet<(FeeRate, TxId)>,
    /// Per sender the pending transactions by nonce.
    pub senders: FastMap<Address, BTreeMap<Nonce, TxId>>,
}

pub fn new(limits: MempoolLimits) -> Mempool {
    Mempool {
        limits,
        bytes: 0,
        txs: FastMap::default(),
        by_fee: BTreeSet::new(),
        senders: FastMap::default(),
    }
}

/// A count of pool entries as the `u32` of the API views.
fn counter(len: usize) -> Result<u32, MempoolError> {
    u32::try_from(len).ok().ok_or(MempoolError::TooMany {
        limit: MAX_PENDING_TXS,
    })
}

/// Adds an accepted transaction under its `id`, the txid the caller computed once. The
/// module doc lists the replacement and eviction rules. On `Err` the pool is unchanged.
///
/// # Panics
///
/// When the byte total, the fee index or the sender queue do not account for a pending
/// transaction, which this function rules out.
pub fn insert(pool: &mut Mempool, id: TxId, tx: SignedTx) -> Result<TxId, MempoolError> {
    if pool.txs.contains_key(&id) {
        return Err(MempoolError::Duplicate(id));
    }
    if let TxKind::RegisterCircuit {
        verifying_key,
        circuit,
        ..
    } = &tx.body.kind
    {
        let found = verifying_key.len().saturating_add(circuit.len());
        if found > MAX_RELAY_CIRCUIT_BYTES {
            return Err(MempoolError::OverRelayCap {
                found,
                limit: MAX_RELAY_CIRCUIT_BYTES,
            });
        }
    }
    let bytes = encoded_len(&tx);
    let size = u32::try_from(bytes)
        .ok()
        .ok_or(MempoolError::Oversized { bytes })?;
    let rate = FeeRate {
        fee: tx.body.fee,
        size,
    };
    let (sender, nonce) = (tx.body.sender, tx.body.nonce);
    let queue = pool.senders.get(&sender);
    let replaced = queue.and_then(|queue| queue.get(&nonce)).copied();
    let freed = if let Some(old_id) = replaced {
        let old = pool
            .txs
            .get(&old_id)
            .expect("the sender queue holds pending transactions");
        if tx.body.fee <= old.tx.body.fee {
            return Err(MempoolError::Underpriced {
                existing: old_id,
                fee: old.tx.body.fee,
            });
        }
        old.bytes
    } else {
        let slots = queue.map_or(0, BTreeMap::len);
        if slots >= pool.limits.sender_slots {
            return Err(MempoolError::SenderFull {
                sender,
                slots: pool.limits.sender_slots,
            });
        }
        counter(pool.txs.len().saturating_add(1))?;
        0
    };
    let full = MempoolError::Full {
        max_bytes: pool.limits.max_bytes,
    };
    let held = pool
        .bytes
        .checked_sub(freed)
        .expect("the total counts every pending transaction");
    let total = held.checked_add(bytes).ok_or(full.clone())?;
    let victims = match total.checked_sub(pool.limits.max_bytes) {
        Some(over) if over > 0 => eviction_plan(pool, over, &rate, replaced).ok_or(full)?,
        _ => Vec::new(),
    };
    for gone in replaced.iter().chain(&victims) {
        remove(pool, gone);
    }
    pool.bytes = pool
        .bytes
        .checked_add(bytes)
        .expect("the plan checked the total");
    pool.by_fee.insert((rate, id));
    pool.senders.entry(sender).or_default().insert(nonce, id);
    pool.txs.insert(id, Pending { tx, bytes, rate });
    Ok(id)
}

/// The lowest paying transactions whose removal frees `over` bytes, all with a rate
/// below `rate`, or `None` when they do not free enough. `skip` is the transaction the
/// new one replaces, whose bytes the caller counted already.
fn eviction_plan(
    pool: &Mempool,
    over: usize,
    rate: &FeeRate,
    skip: Option<TxId>,
) -> Option<Vec<TxId>> {
    let mut missing = over;
    let mut victims = Vec::new();
    for (victim_rate, victim) in &pool.by_fee {
        if victim_rate >= rate {
            break;
        }
        if Some(*victim) == skip {
            continue;
        }
        let held = pool.txs.get(victim)?;
        victims.push(*victim);
        missing = missing.saturating_sub(held.bytes);
        if missing == 0 {
            return Some(victims);
        }
    }
    None
}

/// # Panics
///
/// When the byte total, the fee index or the sender queue do not account for the
/// transaction, which [`insert`] rules out.
pub fn remove(pool: &mut Mempool, id: &TxId) -> Option<SignedTx> {
    let Pending { tx, bytes, rate } = pool.txs.remove(id)?;
    pool.bytes = pool
        .bytes
        .checked_sub(bytes)
        .expect("the total counts every pending transaction");
    assert!(
        pool.by_fee.remove(&(rate, *id)),
        "the fee index holds every pending transaction"
    );
    let queue = pool
        .senders
        .get_mut(&tx.body.sender)
        .expect("a sender with a pending transaction has a queue");
    assert!(
        queue.remove(&tx.body.nonce).is_some(),
        "the queue holds every pending transaction of its sender"
    );
    if queue.is_empty() {
        pool.senders.remove(&tx.body.sender);
    }
    Some(tx)
}

/// Removes the pending transactions of `sender` with a nonce up to `nonce`, which a
/// block of the chain made stale by using that nonce. Returns how many were pending.
pub fn remove_through(pool: &mut Mempool, sender: &Address, nonce: Nonce) -> usize {
    let stale: Vec<TxId> = pool
        .senders
        .get(sender)
        .map(|queue| queue.range(..=nonce).map(|(_, id)| *id).collect())
        .unwrap_or_default();
    stale.iter().filter(|id| remove(pool, id).is_some()).count()
}

/// The bodies of the pending transactions of `sender` with a nonce below `nonce`, in
/// nonce order. They take their cost from the balance before a transaction with
/// `nonce` does, see `pouw_consensus::check_admission`.
pub fn queued_before<'p>(pool: &'p Mempool, sender: &Address, nonce: Nonce) -> Vec<&'p TxBody> {
    let Some(queue) = pool.senders.get(sender) else {
        return Vec::new();
    };
    queue
        .range(..nonce)
        .filter_map(|(_, id)| pool.txs.get(id))
        .map(|pending| &pending.tx.body)
        .collect()
}

pub fn get<'p>(pool: &'p Mempool, id: &TxId) -> Option<&'p SignedTx> {
    pool.txs.get(id).map(|pending| &pending.tx)
}

/// All pending transactions in no particular order.
pub fn iter(pool: &Mempool) -> impl Iterator<Item = (&TxId, &SignedTx)> {
    pool.txs.iter().map(|(id, pending)| (id, &pending.tx))
}

pub fn proof_requests(pool: &Mempool) -> impl Iterator<Item = (&TxId, &SignedTx)> {
    iter(pool).filter(|(_, tx)| matches!(tx.body.kind, TxKind::ProofRequest { .. }))
}

/// Pending proof requests per circuit, for the `mempool_snapshot` event.
pub fn by_circuit(pool: &Mempool) -> BTreeMap<CircuitId, u64> {
    let mut counts = BTreeMap::new();
    for (_, tx) in proof_requests(pool) {
        if let TxKind::ProofRequest { circuit, .. } = &tx.body.kind {
            counts
                .entry(*circuit)
                .and_modify(|count: &mut u64| *count = count.saturating_add(1))
                .or_insert(1);
        }
    }
    counts
}

/// The summary the `mempool_snapshot` event carries.
pub fn snapshot(pool: &Mempool) -> MempoolSnapshot {
    MempoolSnapshot {
        pending_txs: count(pool.txs.len()),
        pending_proof_requests: count(proof_requests(pool).count()),
        by_circuit: by_circuit(pool),
    }
}

/// The answer of `GET /v1/mempool`, with the txids by ascending id.
///
/// # Panics
///
/// When the pool holds more than [`MAX_PENDING_TXS`] transactions, which [`insert`]
/// rules out.
pub fn view(pool: &Mempool) -> MempoolView {
    let cap = "insert caps the pool at MAX_PENDING_TXS";
    let mut txids: Vec<TxId> = pool.txs.keys().copied().collect();
    txids.sort_unstable();
    MempoolView {
        tx_count: counter(pool.txs.len()).expect(cap),
        proof_request_count: counter(proof_requests(pool).count()).expect(cap),
        txids,
    }
}

/// A length as a counter of events and metrics, saturating at `u64::MAX`.
pub fn count(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use pouw_crypto::{Address, Hash32, SigningKey};
    use pouw_types::{Amount, Block, ChainId, Nonce, TxBody, sign_body, txid};

    use pouw_types::{U32, U64};

    use super::*;

    fn tx(nonce: u64, kind: TxKind) -> SignedTx {
        let key = SigningKey::from_seed([1; 32]);
        sign_body(
            &TxBody {
                chain_id: ChainId(1),
                sender: key.address(),
                nonce: Nonce(nonce),
                fee: Amount(1),
                kind,
            },
            &key,
        )
    }

    fn add(pool: &mut Mempool, tx: SignedTx) -> Result<TxId, MempoolError> {
        insert(pool, txid(&tx), tx)
    }

    fn drop_block(pool: &mut Mempool, block: &Block) -> usize {
        let mut ids = Vec::new();
        block.txids_into(&mut ids);
        ids.iter().filter(|id| remove(pool, id).is_some()).count()
    }

    fn request(nonce: u64) -> SignedTx {
        tx(
            nonce,
            TxKind::ProofRequest {
                circuit: CircuitId(TxId(Hash32([3; 32]))),
                public_inputs: vec![],
                witness: Box::from([]),
            },
        )
    }

    fn transfer(nonce: u64) -> SignedTx {
        tx(
            nonce,
            TxKind::Transfer {
                to: Address([2; 32]),
                amount: Amount(1),
            },
        )
    }

    #[test]
    fn requests_are_listed_apart() {
        let mut pool = empty(LIMITS);
        for n in 0..20 {
            add(&mut pool, request(n)).unwrap();
        }
        add(&mut pool, transfer(99)).unwrap();
        assert_eq!(proof_requests(&pool).count(), 20);
        assert_eq!(pool.txs.len() - proof_requests(&pool).count(), 1);
        assert_eq!(by_circuit(&pool).values().sum::<u64>(), 20);
    }

    fn empty(limits: MempoolLimits) -> Mempool {
        new(limits)
    }

    const LIMITS: MempoolLimits = MempoolLimits {
        max_bytes: 4 << 20,
        sender_slots: 100,
    };

    fn size(tx: &SignedTx) -> usize {
        pouw_types::encoded_len(tx)
    }

    #[test]
    fn a_byte_total_that_overflows_is_refused() {
        let mut pool = empty(MempoolLimits {
            max_bytes: usize::MAX,
            sender_slots: 100,
        });
        pool.bytes = usize::MAX - 1;
        let tx = transfer(0);
        assert!(size(&tx) > 1);
        assert_eq!(
            add(&mut pool, tx),
            Err(MempoolError::Full {
                max_bytes: usize::MAX
            })
        );
        assert_eq!(pool.bytes, usize::MAX - 1);
    }

    #[test]
    fn duplicates_are_refused() {
        let mut pool = empty(LIMITS);
        let id = add(&mut pool, transfer(0)).unwrap();
        assert_eq!(
            add(&mut pool, transfer(0)),
            Err(MempoolError::Duplicate(id))
        );
    }

    #[test]
    fn the_pool_is_full_by_bytes_not_by_entries() {
        let each = size(&transfer(0));
        let mut pool = empty(MempoolLimits {
            max_bytes: 2 * each,
            sender_slots: 100,
        });
        let id = add(&mut pool, transfer(0)).unwrap();
        add(&mut pool, transfer(1)).unwrap();
        assert_eq!(pool.bytes, 2 * each);
        assert_eq!(
            add(&mut pool, transfer(2)),
            Err(MempoolError::Full {
                max_bytes: 2 * each
            })
        );
        remove(&mut pool, &id);
        assert_eq!(pool.bytes, each);
        add(&mut pool, transfer(2)).unwrap();
    }

    #[test]
    fn one_big_transaction_takes_the_room_of_many() {
        let small = size(&transfer(0));
        let big = circuit_by(1, 0, 4 * small, 100);
        let mut pool = empty(MempoolLimits {
            max_bytes: size(&big),
            sender_slots: 100,
        });
        add(&mut pool, big).unwrap();
        assert!(matches!(
            add(&mut pool, transfer(1)),
            Err(MempoolError::Full { .. })
        ));
    }

    #[test]
    fn a_sender_has_a_bounded_number_of_slots() {
        let mut pool = empty(MempoolLimits {
            max_bytes: 1 << 20,
            sender_slots: 2,
        });
        let ids: Vec<TxId> = (0..2)
            .map(|n| add(&mut pool, transfer(n)).unwrap())
            .collect();
        let sender = transfer(0).body.sender;
        assert_eq!(
            add(&mut pool, transfer(2)),
            Err(MempoolError::SenderFull { sender, slots: 2 })
        );
        remove(&mut pool, &ids[0]);
        add(&mut pool, transfer(2)).unwrap();
    }

    #[test]
    fn a_refused_sender_leaves_no_slot_entry() {
        let mut pool = empty(MempoolLimits {
            max_bytes: 1 << 20,
            sender_slots: 0,
        });
        assert!(matches!(
            add(&mut pool, transfer(0)),
            Err(MempoolError::SenderFull { .. })
        ));
        assert!(pool.senders.is_empty());
    }

    #[test]
    fn included_transactions_free_their_bytes_and_slots() {
        let mut pool = empty(LIMITS);
        add(&mut pool, transfer(0)).unwrap();
        add(&mut pool, transfer(1)).unwrap();
        let block = block_of(vec![transfer(0), transfer(1)]);
        assert_eq!(drop_block(&mut pool, &block), 2);
        assert_eq!(pool.bytes, 0);
        assert_eq!(pool.txs.len(), 0);
    }

    fn circuit(nonce: u64, bytes: usize) -> SignedTx {
        circuit_by(1, nonce, bytes, 1)
    }

    fn circuit_by(seed: u8, nonce: u64, bytes: usize, fee: u64) -> SignedTx {
        let key = SigningKey::from_seed([seed; 32]);
        sign_body(
            &TxBody {
                chain_id: ChainId(1),
                sender: key.address(),
                nonce: Nonce(nonce),
                fee: Amount(fee),
                kind: TxKind::RegisterCircuit {
                    system: pouw_types::ProofSystem::Groth16,
                    constraint_count: pouw_types::ConstraintCount(1),
                    verifying_key: Box::from([1]),
                    circuit: vec![0; bytes].into_boxed_slice(),
                },
            },
            &key,
        )
    }

    #[test]
    fn a_circuit_over_the_relay_cap_is_refused() {
        let mut pool = empty(LIMITS);
        let big = circuit(0, MAX_RELAY_CIRCUIT_BYTES);
        assert_eq!(
            add(&mut pool, big),
            Err(MempoolError::OverRelayCap {
                found: MAX_RELAY_CIRCUIT_BYTES + 1,
                limit: MAX_RELAY_CIRCUIT_BYTES,
            })
        );
        add(&mut pool, circuit(1, MAX_RELAY_CIRCUIT_BYTES - 1)).unwrap();
    }

    fn block_of(txs: Vec<SignedTx>) -> Block {
        Block {
            header: pouw_types::BlockHeader {
                version: U32::new(1),
                chain_id: U32::new(1),
                system_id: U64::new(0),
                height: U64::new(1),
                parent: pouw_types::BlockId::ZERO,
                timestamp: U64::new(0),
                miner: Address([0; 32]),
                tx_root: Hash32::ZERO,
                target: pouw_types::Target([0xff; 32]),
                nonce: U64::new(0),
            },
            txs,
            proof_txs: Vec::new(),
        }
    }

    #[test]
    fn included_transactions_leave_the_pool() {
        let mut pool = empty(LIMITS);
        add(&mut pool, transfer(0)).unwrap();
        add(&mut pool, request(1)).unwrap();
        add(&mut pool, transfer(2)).unwrap();
        let mut block = block_of(vec![transfer(0)]);
        block.proof_txs = vec![pouw_types::ProofTx {
            request: request(1),
            usage_counter: pouw_types::UsageCounter(0),
            proof: Box::from([]),
        }];
        assert_eq!(drop_block(&mut pool, &block), 2);
        assert_eq!(pool.txs.len(), 1);
    }

    fn paid(seed: u8, nonce: u64, fee: u64) -> SignedTx {
        let key = SigningKey::from_seed([seed; 32]);
        sign_body(
            &TxBody {
                chain_id: ChainId(1),
                sender: key.address(),
                nonce: Nonce(nonce),
                fee: Amount(fee),
                kind: TxKind::Transfer {
                    to: Address([2; 32]),
                    amount: Amount(1),
                },
            },
            &key,
        )
    }

    fn fees(pool: &Mempool) -> Vec<u64> {
        pool.by_fee
            .iter()
            .map(|(_, id)| pool.txs[id].tx.body.fee.0)
            .collect()
    }

    fn assert_consistent(pool: &Mempool) {
        assert_eq!(pool.by_fee.len(), pool.txs.len());
        let queued: usize = pool.senders.values().map(BTreeMap::len).sum();
        assert_eq!(queued, pool.txs.len());
        assert!(pool.senders.values().all(|queue| !queue.is_empty()));
        assert_eq!(
            pool.bytes,
            pool.txs
                .values()
                .map(|pending| pending.bytes)
                .sum::<usize>()
        );
        for (rate, id) in &pool.by_fee {
            let pending = &pool.txs[id];
            assert_eq!(*rate, pending.rate);
            assert_eq!(
                pool.senders[&pending.tx.body.sender][&pending.tx.body.nonce],
                *id
            );
        }
    }

    fn rate(fee: u64, size: u32) -> FeeRate {
        FeeRate {
            fee: Amount(fee),
            size,
        }
    }

    #[test]
    fn fee_rates_compare_by_cross_multiplication() {
        assert_eq!(rate(1, 2), rate(2, 4));
        assert!(rate(3, 5) > rate(1, 2));
        assert!(rate(1, 3) < rate(1, 2));
        assert!(rate(1, 1) < rate(u64::MAX - 1, u32::MAX));
        assert!(rate(u64::MAX, u32::MAX) < rate(u64::MAX, u32::MAX - 1));
        assert!(rate(u64::MAX, 1) > rate(u64::MAX - 1, 1));
        assert!(rate(0, 7) < rate(1, u32::MAX));
    }

    #[test]
    fn the_lowest_fee_rate_is_evicted_first() {
        let each = size(&paid(1, 0, 5));
        let mut pool = empty(MempoolLimits {
            max_bytes: 3 * each,
            sender_slots: 10,
        });
        for (seed, fee) in [(1, 5), (2, 1), (3, 3)] {
            add(&mut pool, paid(seed, 0, fee)).unwrap();
        }
        assert_eq!(fees(&pool), [1, 3, 5]);
        add(&mut pool, paid(4, 0, 4)).unwrap();
        assert_eq!(fees(&pool), [3, 4, 5]);
        add(&mut pool, paid(5, 0, 9)).unwrap();
        assert_eq!(fees(&pool), [4, 5, 9]);
        assert_consistent(&pool);
    }

    #[test]
    fn a_transaction_never_evicts_an_equal_or_better_one() {
        let each = size(&paid(1, 0, 5));
        let mut pool = empty(MempoolLimits {
            max_bytes: 2 * each,
            sender_slots: 10,
        });
        add(&mut pool, paid(1, 0, 5)).unwrap();
        add(&mut pool, paid(2, 0, 7)).unwrap();
        for fee in [5, 4, 0] {
            assert!(matches!(
                add(&mut pool, paid(3, 0, fee)),
                Err(MempoolError::Full { .. })
            ));
        }
        assert_eq!(fees(&pool), [5, 7]);
        assert_consistent(&pool);
    }

    #[test]
    fn an_eviction_that_cannot_make_room_evicts_nothing() {
        let small = size(&paid(1, 0, 1));
        let mut pool = empty(MempoolLimits {
            max_bytes: 3 * small,
            sender_slots: 10,
        });
        for (seed, fee) in [(1, 1), (2, 2), (3, 100)] {
            add(&mut pool, paid(seed, 0, fee)).unwrap();
        }
        let big = circuit_by(9, 0, 4 * small, 1000);
        assert!(size(&big) > pool.limits.max_bytes);
        assert!(matches!(
            add(&mut pool, big),
            Err(MempoolError::Full { .. })
        ));
        assert_eq!(fees(&pool), [1, 2, 100]);
        assert_consistent(&pool);
    }

    #[test]
    fn a_big_transaction_evicts_as_many_as_its_bytes_need() {
        let small = size(&paid(1, 0, 1));
        let mut pool = empty(MempoolLimits {
            max_bytes: 4 * small,
            sender_slots: 10,
        });
        for (seed, fee) in [(1, 1), (2, 2), (3, 3), (4, 400)] {
            add(&mut pool, paid(seed, 0, fee)).unwrap();
        }
        let spare = size(&circuit_by(9, 0, 0, 1000));
        let wide = circuit_by(9, 0, 2 * small - spare, 1000);
        assert!(size(&wide) > small);
        add(&mut pool, wide).unwrap();
        assert_eq!(pool.txs.len(), 3);
        assert_eq!(fees(&pool), [3, 400, 1000]);
        assert_consistent(&pool);
    }

    #[test]
    fn a_higher_fee_replaces_the_same_sender_and_nonce() {
        let mut pool = empty(LIMITS);
        let old = add(&mut pool, paid(1, 0, 5)).unwrap();
        add(&mut pool, paid(1, 1, 5)).unwrap();
        let new = add(&mut pool, paid(1, 0, 6)).unwrap();
        assert!(get(&pool, &old).is_none());
        assert!(get(&pool, &new).is_some());
        assert_eq!(pool.txs.len(), 2);
        assert_consistent(&pool);
    }

    #[test]
    fn an_equal_or_lower_fee_does_not_replace() {
        let mut pool = empty(LIMITS);
        let old = add(&mut pool, paid(1, 0, 5)).unwrap();
        let attempts = [paid(1, 0, 4), paid(1, 0, 0), circuit_by(1, 0, 0, 5)];
        for attempt in attempts {
            assert_eq!(
                add(&mut pool, attempt),
                Err(MempoolError::Underpriced {
                    existing: old,
                    fee: Amount(5)
                })
            );
        }
        assert_eq!(fees(&pool), [5]);
        assert_consistent(&pool);
    }

    #[test]
    fn a_replacement_needs_no_free_slot_and_no_free_bytes() {
        let each = size(&paid(1, 0, 5));
        let mut pool = empty(MempoolLimits {
            max_bytes: each,
            sender_slots: 1,
        });
        add(&mut pool, paid(1, 0, 5)).unwrap();
        add(&mut pool, paid(1, 0, 6)).unwrap();
        assert_eq!(fees(&pool), [6]);
        assert_eq!(pool.bytes, each);
        assert_consistent(&pool);
    }

    #[test]
    fn a_refused_replacement_keeps_the_old_transaction() {
        let each = size(&paid(1, 0, 5));
        let mut pool = empty(MempoolLimits {
            max_bytes: 2 * each,
            sender_slots: 5,
        });
        add(&mut pool, paid(1, 0, 5)).unwrap();
        add(&mut pool, paid(2, 0, 50)).unwrap();
        let big = circuit_by(1, 0, 4 * each, 6);
        assert!(matches!(
            add(&mut pool, big),
            Err(MempoolError::Full { .. })
        ));
        assert_eq!(fees(&pool), [5, 50]);
        assert_consistent(&pool);
    }

    #[test]
    fn removal_clears_every_index() {
        let mut pool = empty(LIMITS);
        let first = add(&mut pool, paid(1, 0, 5)).unwrap();
        add(&mut pool, paid(1, 1, 6)).unwrap();
        remove(&mut pool, &first);
        assert_consistent(&pool);
        assert_eq!(pool.senders.len(), 1);
        drop_block(&mut pool, &block_of(vec![paid(1, 1, 6)]));
        assert!(pool.senders.is_empty() && pool.by_fee.is_empty());
        assert_eq!(pool.bytes, 0);
    }

    #[test]
    fn a_used_nonce_makes_the_lower_ones_stale() {
        let mut pool = empty(LIMITS);
        for nonce in 0..4 {
            add(&mut pool, paid(1, nonce, 5)).unwrap();
        }
        add(&mut pool, paid(2, 0, 5)).unwrap();
        let sender = paid(1, 0, 5).body.sender;
        assert_eq!(remove_through(&mut pool, &sender, Nonce(1)), 2);
        assert_eq!(
            pool.senders[&sender].keys().copied().collect::<Vec<_>>(),
            [Nonce(2), Nonce(3)]
        );
        assert_eq!(pool.txs.len(), 3);
        assert_eq!(remove_through(&mut pool, &sender, Nonce(1)), 0);
        assert_consistent(&pool);
    }

    #[test]
    fn counts_over_the_view_width_are_refused() {
        assert_eq!(counter(7), Ok(7));
        if let Ok(len) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert_eq!(
                counter(len),
                Err(MempoolError::TooMany {
                    limit: MAX_PENDING_TXS
                })
            );
        }
    }

    #[test]
    fn the_view_lists_ids_in_order() {
        let mut pool = empty(LIMITS);
        for nonce in 0..5 {
            add(&mut pool, request(nonce)).unwrap();
        }
        add(&mut pool, transfer(9)).unwrap();
        let view = view(&pool);
        assert_eq!((view.tx_count, view.proof_request_count), (6, 5));
        assert!(view.txids.is_sorted());
    }

    /// The admission rules of the module doc, written as plainly as possible over a
    /// list of the pending transactions.
    fn model_insert(
        model: &mut Vec<Pending>,
        limits: MempoolLimits,
        tx: SignedTx,
    ) -> Result<TxId, MempoolError> {
        let id = txid(&tx);
        if model.iter().any(|held| txid(&held.tx) == id) {
            return Err(MempoolError::Duplicate(id));
        }
        let bytes = size(&tx);
        let rate = FeeRate {
            fee: tx.body.fee,
            size: u32::try_from(bytes).unwrap(),
        };
        let same = |held: &Pending| held.tx.body.sender == tx.body.sender;
        let replaced = model
            .iter()
            .position(|held| same(held) && held.tx.body.nonce == tx.body.nonce);
        if let Some(at) = replaced {
            let old = &model[at];
            if tx.body.fee <= old.tx.body.fee {
                return Err(MempoolError::Underpriced {
                    existing: txid(&old.tx),
                    fee: old.tx.body.fee,
                });
            }
        } else if model.iter().filter(|held| same(held)).count() >= limits.sender_slots {
            return Err(MempoolError::SenderFull {
                sender: tx.body.sender,
                slots: limits.sender_slots,
            });
        }
        let mut kept: Vec<Pending> = model
            .iter()
            .enumerate()
            .filter(|(at, _)| Some(*at) != replaced)
            .map(|(_, held)| held.clone())
            .collect();
        let product = |fee: Amount, size: u32| u128::from(fee.0).checked_mul(u128::from(size));
        kept.sort_by_key(|held| txid(&held.tx));
        kept.sort_by(|a, b| {
            product(a.rate.fee, b.rate.size).cmp(&product(b.rate.fee, a.rate.size))
        });
        let held: usize = kept.iter().map(|held| held.bytes).sum();
        let mut total = held.checked_add(bytes).unwrap();
        while total > limits.max_bytes {
            match kept.first() {
                Some(lowest) if lowest.rate < rate => {
                    total = total.checked_sub(kept.remove(0).bytes).unwrap();
                }
                _ => {
                    return Err(MempoolError::Full {
                        max_bytes: limits.max_bytes,
                    });
                }
            }
        }
        kept.push(Pending { tx, bytes, rate });
        *model = kept;
        Ok(id)
    }

    fn model_remove_through(model: &mut Vec<Pending>, sender: &Address, nonce: Nonce) -> usize {
        let before = model.len();
        model.retain(|held| !(held.tx.body.sender == *sender && held.tx.body.nonce <= nonce));
        before.checked_sub(model.len()).unwrap()
    }

    fn ids_of<'a>(pending: impl Iterator<Item = &'a Pending>) -> BTreeSet<TxId> {
        pending.map(|held| txid(&held.tx)).collect()
    }

    #[test]
    fn random_operations_keep_the_pool_equal_to_a_naive_model() {
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move |below: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            usize::try_from(seed % u64::try_from(below).unwrap()).unwrap()
        };
        let wide = |value: usize| u64::try_from(value).unwrap();
        let seeds = [1u8, 2, 3, 4];
        let limits = MempoolLimits {
            max_bytes: size(&paid(1, 0, 0)).checked_mul(6).unwrap(),
            sender_slots: 3,
        };
        let mut pool = empty(limits);
        let mut model: Vec<Pending> = Vec::new();
        let mut orphans: Vec<SignedTx> = Vec::new();
        let mut refusals = 0usize;
        for _ in 0..600 {
            let mut pending: Vec<SignedTx> =
                pool.txs.values().map(|held| held.tx.clone()).collect();
            pending.sort_by_key(txid);
            match next(6) {
                0 | 1 => {
                    let (seed, nonce, fee) = (seeds[next(4)], wide(next(6)), wide(next(8)));
                    let tx = if next(3) == 0 {
                        circuit_by(seed, nonce, next(80), fee)
                    } else {
                        paid(seed, nonce, fee)
                    };
                    let expected = model_insert(&mut model, limits, tx.clone());
                    if expected.is_err() {
                        refusals = refusals.checked_add(1).unwrap();
                    }
                    assert_eq!(add(&mut pool, tx), expected);
                }
                2 if !pending.is_empty() => {
                    let gone = &pending[next(pending.len())];
                    let id = txid(gone);
                    model.retain(|held| txid(&held.tx) != id);
                    assert_eq!(remove(&mut pool, &id).as_ref(), Some(gone));
                    orphans.push(gone.clone());
                }
                3 if !pending.is_empty() => {
                    let included = if next(2) == 0 {
                        pending[next(pending.len())].clone()
                    } else {
                        paid(seeds[next(4)], wide(next(6)), 100)
                    };
                    let was_pending = usize::from(pending.contains(&included));
                    let (sender, nonce) = (included.body.sender, included.body.nonce);
                    let expected = model_remove_through(&mut model, &sender, nonce);
                    let block = block_of(vec![included.clone()]);
                    assert_eq!(drop_block(&mut pool, &block), was_pending);
                    let stale = remove_through(&mut pool, &sender, nonce);
                    assert_eq!(Some(stale), expected.checked_sub(was_pending));
                    orphans.push(included);
                }
                4 if !orphans.is_empty() => {
                    let back = orphans.swap_remove(next(orphans.len()));
                    let expected = model_insert(&mut model, limits, back.clone());
                    assert_eq!(add(&mut pool, back), expected);
                }
                5 if !pending.is_empty() => {
                    let old = &pending[next(pending.len())];
                    let fee = [
                        old.body.fee.0.checked_sub(1),
                        Some(old.body.fee.0),
                        old.body.fee.0.checked_add(1),
                    ][next(3)]
                    .unwrap_or(0);
                    let seed = *seeds
                        .iter()
                        .find(|seed| paid(**seed, 0, 0).body.sender == old.body.sender)
                        .unwrap();
                    let nonce = old.body.nonce.0;
                    let tx = match old.body.kind {
                        TxKind::Transfer { .. } => circuit_by(seed, nonce, 0, fee),
                        _ => paid(seed, nonce, fee),
                    };
                    let expected = model_insert(&mut model, limits, tx.clone());
                    assert_eq!(add(&mut pool, tx), expected);
                }
                _ => {}
            }
            assert_eq!(ids_of(pool.txs.values()), ids_of(model.iter()));
            assert_consistent(&pool);
        }
        assert!(refusals > 0 && !pool.txs.is_empty());
    }
}
