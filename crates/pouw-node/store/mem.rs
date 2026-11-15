//! The in-memory backend of [`super::Store`]. It holds the tables of
//! [`super::schema`] as maps, with values in the byte layout of the schema (a block
//! body is kept as encoded bytes, as a database would keep it).

use pouw_consensus::{ChainTip, MemState, StateDiff, StateError, StateView, state};
use pouw_crypto::Address;
use pouw_types::{
    Account, BlockHeader, BlockId, BlockMap, CircuitEntry, CircuitId, FastMap, Height, TxId,
    UsageCounter,
};

use super::{
    StoreError, TxLocation,
    schema::{IndexEntry, Meta, TxEntry},
};

#[derive(Debug, Default)]
pub struct Mem {
    /// Table `meta`.
    pub meta: Meta,
    /// Table `headers`. The store cannot tell whether the caller of `put_header` checked
    /// the proof of work of an id (headers of a sync answer arrive without a precheck),
    /// so the key may be unchecked and the map is a [`FastMap`].
    pub headers: FastMap<BlockId, BlockHeader>,
    /// Table `block_index`, keyed like `headers`.
    pub block_index: FastMap<BlockId, IndexEntry>,
    /// Table `bodies`: the whole block as received, its first bytes are the header.
    /// A body is stored only from a block whose proof of work is checked, so the key
    /// is a checked id.
    pub bodies: BlockMap<Box<[u8]>>,
    /// Table `canonical`: the id at height `i` is element `i`.
    pub canonical: Vec<BlockId>,
    /// Table `undo`: a record exists only for a connected block, so the key is a checked id.
    pub undo: BlockMap<StateDiff>,
    /// Table `tx_index`. A txid is grindable, so the map is a [`FastMap`].
    pub tx_index: FastMap<TxId, TxEntry>,
    /// The state tables.
    pub state: MemState,
}

pub fn schema_version(view: &Mem) -> u32 {
    view.meta.schema_version
}

pub fn index(view: &Mem, id: &BlockId) -> Option<IndexEntry> {
    view.block_index.get(id).copied()
}

fn tip_at(view: &Mem, id: &BlockId) -> Result<ChainTip, StoreError> {
    let entry = index(view, id)
        .ok_or_else(|| StoreError::Corrupt(format!("canonical block {id} is not indexed")))?;
    Ok(ChainTip {
        id: *id,
        height: entry.height(),
        cumulative_work: entry.work(),
    })
}

pub fn tip(view: &Mem) -> Result<Option<ChainTip>, StoreError> {
    view.meta
        .tip
        .as_ref()
        .map(|id| tip_at(view, id))
        .transpose()
}

pub fn parent_of_tip(view: &Mem) -> Result<Option<ChainTip>, StoreError> {
    view.canonical
        .len()
        .checked_sub(2)
        .and_then(|i| view.canonical.get(i))
        .map(|id| tip_at(view, id))
        .transpose()
}

pub fn header<'v>(view: &'v Mem, id: &BlockId) -> Option<&'v BlockHeader> {
    view.headers.get(id)
}

pub fn stored_block<'v>(view: &'v Mem, id: &BlockId) -> Option<&'v [u8]> {
    view.bodies.get(id).map(AsRef::as_ref)
}

pub fn canonical_id(view: &Mem, height: Height) -> Option<BlockId> {
    let index = usize::try_from(height.0).ok()?;
    view.canonical.get(index).copied()
}

pub fn tx_entry(view: &Mem, id: &TxId) -> Option<TxEntry> {
    view.tx_index.get(id).copied()
}

pub fn account(view: &Mem, address: &Address) -> Result<Option<Account>, StateError> {
    view.state.account(address)
}

pub fn circuit<'v>(view: &'v Mem, id: &CircuitId) -> Result<Option<&'v CircuitEntry>, StateError> {
    view.state.circuit(id)
}

/// Every registered circuit, ascending by height of registration and then by id.
pub fn circuits(view: &Mem) -> Vec<CircuitEntry> {
    let mut entries: Vec<CircuitEntry> = view.state.circuits.values().cloned().collect();
    entries.sort_by_key(|entry| (entry.registered_at, entry.id));
    entries
}

pub fn usage_counter(
    view: &Mem,
    miner: &Address,
    circuit: &CircuitId,
) -> Result<Option<UsageCounter>, StateError> {
    view.state.usage_counter(miner, circuit)
}

pub fn insert_header(mem: &mut Mem, id: BlockId, header: BlockHeader, entry: IndexEntry) {
    mem.headers.insert(id, header);
    mem.block_index.insert(id, entry);
}

pub fn insert_body(mem: &mut Mem, id: BlockId, bytes: &[u8], entry: IndexEntry) {
    mem.bodies.insert(id, bytes.into());
    mem.block_index.insert(id, entry);
}

pub fn set_index(mem: &mut Mem, id: BlockId, entry: IndexEntry) {
    mem.block_index.insert(id, entry);
}

/// Writes everything of a connect: the state first, the only step that can fail, so an
/// error leaves every table as it was.
pub fn connect(
    mem: &mut Mem,
    new_tip: &ChainTip,
    entry: IndexEntry,
    locations: Vec<(TxId, TxEntry)>,
    diff: &StateDiff,
) -> Result<(), StoreError> {
    state::apply(&mut mem.state, diff)?;
    mem.tx_index.extend(locations);
    mem.undo.insert(new_tip.id, diff.clone());
    mem.block_index.insert(new_tip.id, entry);
    mem.canonical.push(new_tip.id);
    mem.meta.tip = Some(new_tip.id);
    if new_tip.height == Height(0) {
        mem.meta.genesis = Some(new_tip.id);
    }
    Ok(())
}

pub fn disconnect(
    mem: &mut Mem,
    tip: &BlockId,
    entry: IndexEntry,
    parent: &BlockId,
    txids: &[TxId],
) -> Result<(), StoreError> {
    let undo = mem
        .undo
        .get(tip)
        .ok_or_else(|| StoreError::Corrupt(format!("tip {tip} has no undo data")))?
        .inverse();
    state::apply(&mut mem.state, &undo)?;
    for id in txids {
        mem.tx_index.remove(id);
    }
    mem.undo.remove(tip);
    mem.canonical.pop();
    mem.block_index.insert(*tip, entry);
    mem.meta.tip = Some(*parent);
    Ok(())
}

pub fn tx_location(view: &Mem, id: &TxId) -> Result<Option<TxLocation>, StoreError> {
    let Some(entry) = tx_entry(view, id) else {
        return Ok(None);
    };
    let block = index(view, &entry.block)
        .ok_or_else(|| StoreError::Corrupt(format!("tx block {} is not indexed", entry.block)))?;
    Ok(Some(TxLocation {
        block: entry.block,
        height: block.height(),
        index: entry.index.get(),
    }))
}
