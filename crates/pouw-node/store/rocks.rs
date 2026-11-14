//! The `RocksDB` backend of [`super::Store`] (pouw-node#69), built with the `rocksdb`
//! feature. It holds the tables of [`super::schema`], one column family each:
//!
//! | column family    | key                              | value                          |
//! | ---------------- | -------------------------------- | ------------------------------ |
//! | `meta`           | `schema_version`, `genesis`, `tip` | u32 little-endian, block id  |
//! | `headers`        | block id                         | the 168 byte header            |
//! | `block_index`    | block id                         | the 41 byte `IndexEntry`       |
//! | `bodies`         | block id                         | the received block bytes       |
//! | `canonical`      | height, u64 big-endian           | block id                       |
//! | `undo`           | block id                         | borsh `StateDiff`              |
//! | `tx_index`       | txid                             | the 36 byte `TxEntry`          |
//! | `accounts`       | address                          | borsh `Account`                |
//! | `circuits`       | circuit id                       | borsh `CircuitEntry`           |
//! | `usage_counters` | miner address, circuit id        | borsh `UsageCounter`           |
//!
//! Every write is one `WriteBatch`, so it lands completely or not at all. `connect` and
//! `disconnect`, which the chain state depends on, are written with `sync`, so a block
//! the store answered for survives a crash. A header, a body and an index change are not
//! synced: a lost one is fetched again and the tables stay consistent, because each of
//! them is one batch.
//!
//! # What stays in memory
//!
//! Readers of [`super::StateView`] lend a `&CircuitEntry` and [`super::header`] lends a
//! `&BlockHeader`, and `RocksDB` hands out owned bytes. So `Db` keeps a copy of the
//! `headers` and `circuits` tables in memory, read when the store is opened and updated
//! after each write that succeeded. A header is 168 bytes. The circuit registry holds
//! the circuits and verifying keys, up to megabytes each, which is what the node needs
//! in memory to verify proofs anyway. Block bodies are read from the database on each
//! request.

use std::{borrow::Cow, fmt, fs, path::Path};

use borsh::BorshDeserialize;
use pouw_consensus::{ChainTip, DiffMismatch, StateDiff, StateError};
use pouw_crypto::{Address, Hash32};
use pouw_types::{
    Account, BlockHeader, BlockId, CircuitEntry, CircuitId, FastMap, Height, TxId, UsageCounter,
};
use rocksdb::{
    ColumnFamily, ColumnFamilyDescriptor, DB, IteratorMode, Options, WriteBatch, WriteOptions,
};
use zerocopy::{FromBytes, IntoBytes};

use super::{
    StoreError, TxLocation,
    schema::{IndexEntry, SCHEMA_VERSION, TxEntry},
};

const META: &str = "meta";
const HEADERS: &str = "headers";
const BLOCK_INDEX: &str = "block_index";
const BODIES: &str = "bodies";
const CANONICAL: &str = "canonical";
const UNDO: &str = "undo";
const TX_INDEX: &str = "tx_index";
const ACCOUNTS: &str = "accounts";
const CIRCUITS: &str = "circuits";
const USAGE_COUNTERS: &str = "usage_counters";

const TABLES: [&str; 10] = [
    META,
    HEADERS,
    BLOCK_INDEX,
    BODIES,
    CANONICAL,
    UNDO,
    TX_INDEX,
    ACCOUNTS,
    CIRCUITS,
    USAGE_COUNTERS,
];

const KEY_SCHEMA: &[u8] = b"schema_version";
const KEY_GENESIS: &[u8] = b"genesis";
const KEY_TIP: &[u8] = b"tip";

/// The open database and the in-memory copies of the tables that readers borrow from.
pub struct Db {
    #[expect(
        clippy::struct_field_names,
        reason = "the handle of the database, named after its type"
    )]
    db: DB,
    /// Table `headers`.
    headers: FastMap<BlockId, BlockHeader>,
    /// The `circuits` state table.
    circuits: FastMap<CircuitId, CircuitEntry>,
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Db")
            .field("headers", &self.headers.len())
            .field("circuits", &self.circuits.len())
            .finish_non_exhaustive()
    }
}

fn backend(error: rocksdb::Error) -> StoreError {
    StoreError::Backend(error.into_string())
}

fn state_error(error: &StoreError) -> StateError {
    StateError::Backend(error.to_string())
}

fn corrupt(what: &str) -> StoreError {
    StoreError::Corrupt(what.to_owned())
}

fn family<'d>(db: &'d DB, table: &str) -> Result<&'d ColumnFamily, StoreError> {
    db.cf_handle(table)
        .ok_or_else(|| StoreError::Corrupt(format!("column family {table} is missing")))
}

fn get(db: &DB, table: &str, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
    db.get_cf(family(db, table)?, key).map_err(backend)
}

fn commit(db: &DB, batch: WriteBatch, sync: bool) -> Result<(), StoreError> {
    let mut options = WriteOptions::default();
    options.set_sync(sync);
    db.write_opt(batch, &options).map_err(backend)
}

fn id_from(bytes: &[u8]) -> Result<BlockId, StoreError> {
    let array = <[u8; 32]>::try_from(bytes)
        .ok()
        .ok_or_else(|| corrupt("a key or value is not 32 bytes"))?;
    Ok(BlockId(Hash32(array)))
}

fn decode<T: FromBytes>(bytes: &[u8], what: &str) -> Result<T, StoreError> {
    T::read_from_bytes(bytes)
        .ok()
        .ok_or_else(|| StoreError::Corrupt(format!("a {what} row has {} bytes", bytes.len())))
}

fn unborsh<T: BorshDeserialize>(bytes: &[u8]) -> Result<T, StoreError> {
    borsh::from_slice(bytes).map_err(StoreError::Decode)
}

fn usage_key(miner: &Address, circuit: &CircuitId) -> [u8; 64] {
    let mut key = [0_u8; 64];
    key[..32].copy_from_slice(&miner.0);
    key[32..].copy_from_slice(&circuit.0.0.0);
    key
}

fn mismatch(key: &impl fmt::Debug) -> StoreError {
    StoreError::Diff(DiffMismatch {
        key: format!("{key:?}"),
    })
}

/// Opens the database under `path`, creating it and its column families when they do
/// not exist, and reads the headers and the circuit registry into memory.
pub fn open(path: &Path) -> Result<Db, StoreError> {
    fs::create_dir_all(path).map_err(|error| {
        StoreError::Backend(format!("cannot create {}: {error}", path.display()))
    })?;
    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    let families = TABLES
        .iter()
        .map(|name| ColumnFamilyDescriptor::new(*name, Options::default()));
    let db = DB::open_cf_descriptors(&options, path, families).map_err(backend)?;
    if get(&db, META, KEY_SCHEMA)?.is_none() {
        put_schema_version(&db, SCHEMA_VERSION)?;
    }
    let mut headers = FastMap::default();
    for row in db.iterator_cf(family(&db, HEADERS)?, IteratorMode::Start) {
        let (key, value) = row.map_err(backend)?;
        headers.insert(id_from(&key)?, decode::<BlockHeader>(&value, "header")?);
    }
    let mut circuits = FastMap::default();
    for row in db.iterator_cf(family(&db, CIRCUITS)?, IteratorMode::Start) {
        let (key, value) = row.map_err(backend)?;
        let id = CircuitId(TxId(id_from(&key)?.0));
        circuits.insert(id, unborsh::<CircuitEntry>(&value)?);
    }
    Ok(Db {
        db,
        headers,
        circuits,
    })
}

fn put_schema_version(db: &DB, version: u32) -> Result<(), StoreError> {
    let mut batch = WriteBatch::default();
    batch.put_cf(family(db, META)?, KEY_SCHEMA, version.to_le_bytes());
    commit(db, batch, true)
}

/// Overwrites the stored schema version, for the test of a store written by another
/// version of the node.
#[cfg(test)]
pub fn set_schema_version(rocks: &Db, version: u32) -> Result<(), StoreError> {
    put_schema_version(&rocks.db, version)
}

pub fn schema_version(view: &Db) -> Result<u32, StoreError> {
    let bytes =
        get(&view.db, META, KEY_SCHEMA)?.ok_or_else(|| corrupt("the schema version is missing"))?;
    let array = <[u8; 4]>::try_from(bytes.as_slice())
        .ok()
        .ok_or_else(|| corrupt("the schema version is not 4 bytes"))?;
    Ok(u32::from_le_bytes(array))
}

pub fn index(view: &Db, id: &BlockId) -> Result<Option<IndexEntry>, StoreError> {
    get(&view.db, BLOCK_INDEX, &id.0.0)?
        .map(|bytes| decode::<IndexEntry>(&bytes, "block_index"))
        .transpose()
}

fn meta_id(view: &Db, key: &[u8]) -> Result<Option<BlockId>, StoreError> {
    get(&view.db, META, key)?
        .map(|bytes| id_from(&bytes))
        .transpose()
}

fn tip_at(view: &Db, id: &BlockId) -> Result<ChainTip, StoreError> {
    let entry = index(view, id)?
        .ok_or_else(|| StoreError::Corrupt(format!("canonical block {id} is not indexed")))?;
    Ok(ChainTip {
        id: *id,
        height: entry.height(),
        cumulative_work: entry.work(),
    })
}

pub fn tip(view: &Db) -> Result<Option<ChainTip>, StoreError> {
    meta_id(view, KEY_TIP)?
        .map(|id| tip_at(view, &id))
        .transpose()
}

pub fn parent_of_tip(view: &Db) -> Result<Option<ChainTip>, StoreError> {
    let Some(tip) = tip(view)? else {
        return Ok(None);
    };
    let Some(parent_height) = tip.height.0.checked_sub(1) else {
        return Ok(None);
    };
    canonical_id(view, Height(parent_height))?
        .map(|id| tip_at(view, &id))
        .transpose()
}

pub fn header<'v>(view: &'v Db, id: &BlockId) -> Result<Option<&'v BlockHeader>, StoreError> {
    Ok(view.headers.get(id))
}

pub fn stored_block<'v>(view: &'v Db, id: &BlockId) -> Result<Option<Cow<'v, [u8]>>, StoreError> {
    Ok(get(&view.db, BODIES, &id.0.0)?.map(Cow::Owned))
}

pub fn canonical_id(view: &Db, height: Height) -> Result<Option<BlockId>, StoreError> {
    get(&view.db, CANONICAL, &height.0.to_be_bytes())?
        .map(|bytes| id_from(&bytes))
        .transpose()
}

pub fn tx_location(view: &Db, id: &TxId) -> Result<Option<TxLocation>, StoreError> {
    let Some(bytes) = get(&view.db, TX_INDEX, &id.0.0)? else {
        return Ok(None);
    };
    let entry = decode::<TxEntry>(&bytes, "tx_index")?;
    let block = index(view, &entry.block)?
        .ok_or_else(|| StoreError::Corrupt(format!("tx block {} is not indexed", entry.block)))?;
    Ok(Some(TxLocation {
        block: entry.block,
        height: block.height(),
        index: entry.index.get(),
    }))
}

pub fn account(view: &Db, address: &Address) -> Result<Option<Account>, StateError> {
    get(&view.db, ACCOUNTS, &address.0)
        .map_err(|error| state_error(&error))?
        .map(|bytes| {
            borsh::from_slice(&bytes)
                .map_err(|error| StateError::Corrupt(format!("an account row: {error}")))
        })
        .transpose()
}

pub fn circuit<'v>(view: &'v Db, id: &CircuitId) -> Result<Option<&'v CircuitEntry>, StateError> {
    Ok(view.circuits.get(id))
}

pub fn circuits(view: &Db) -> Result<Vec<CircuitEntry>, StoreError> {
    match *view {}
}

pub fn usage_counter(
    view: &Db,
    miner: &Address,
    circuit: &CircuitId,
) -> Result<Option<UsageCounter>, StateError> {
    get(&view.db, USAGE_COUNTERS, &usage_key(miner, circuit))
        .map_err(|error| state_error(&error))?
        .map(|bytes| {
            borsh::from_slice(&bytes)
                .map_err(|error| StateError::Corrupt(format!("a usage counter row: {error}")))
        })
        .transpose()
}

pub fn insert_header(
    rocks: &mut Db,
    id: BlockId,
    header: BlockHeader,
    entry: IndexEntry,
) -> Result<(), StoreError> {
    let mut batch = WriteBatch::default();
    batch.put_cf(family(&rocks.db, HEADERS)?, id.0.0, header.as_bytes());
    batch.put_cf(family(&rocks.db, BLOCK_INDEX)?, id.0.0, entry.as_bytes());
    commit(&rocks.db, batch, false)?;
    rocks.headers.insert(id, header);
    Ok(())
}

pub fn insert_body(
    rocks: &mut Db,
    id: BlockId,
    bytes: &[u8],
    entry: IndexEntry,
) -> Result<(), StoreError> {
    let mut batch = WriteBatch::default();
    batch.put_cf(family(&rocks.db, BODIES)?, id.0.0, bytes);
    batch.put_cf(family(&rocks.db, BLOCK_INDEX)?, id.0.0, entry.as_bytes());
    commit(&rocks.db, batch, false)
}

pub fn set_index(rocks: &mut Db, id: BlockId, entry: IndexEntry) -> Result<(), StoreError> {
    let mut batch = WriteBatch::default();
    batch.put_cf(family(&rocks.db, BLOCK_INDEX)?, id.0.0, entry.as_bytes());
    commit(&rocks.db, batch, false)
}

/// Adds to `batch` the writes of `diff`, after checking that every `before` value is the
/// one in the database. Nothing is written here, so a mismatch leaves the store as it was.
fn stage_diff(db: &Db, batch: &mut WriteBatch, diff: &StateDiff) -> Result<(), StoreError> {
    for (address, change) in &diff.accounts {
        if account(db, address)? != change.before {
            return Err(mismatch(address));
        }
        let table = family(&db.db, ACCOUNTS)?;
        match &change.after {
            Some(value) => batch.put_cf(
                table,
                address.0,
                borsh::to_vec(value).map_err(StoreError::Encode)?,
            ),
            None => batch.delete_cf(table, address.0),
        }
    }
    for (id, change) in &diff.circuits {
        if db.circuits.get(id) != change.before.as_ref() {
            return Err(mismatch(id));
        }
        let table = family(&db.db, CIRCUITS)?;
        match &change.after {
            Some(value) => batch.put_cf(
                table,
                id.0.0.0,
                borsh::to_vec(value).map_err(StoreError::Encode)?,
            ),
            None => batch.delete_cf(table, id.0.0.0),
        }
    }
    for ((miner, circuit), change) in &diff.usage_counters {
        if usage_counter(db, miner, circuit)? != change.before {
            return Err(mismatch(&(miner, circuit)));
        }
        let table = family(&db.db, USAGE_COUNTERS)?;
        let key = usage_key(miner, circuit);
        match &change.after {
            Some(value) => {
                batch.put_cf(
                    table,
                    key,
                    borsh::to_vec(value).map_err(StoreError::Encode)?,
                );
            }
            None => batch.delete_cf(table, key),
        }
    }
    Ok(())
}

/// Brings the in-memory registry to the state `diff` left in the database.
fn refresh_circuits(rocks: &mut Db, diff: &StateDiff) {
    for (id, change) in &diff.circuits {
        match &change.after {
            Some(entry) => {
                rocks.circuits.insert(*id, entry.clone());
            }
            None => {
                rocks.circuits.remove(id);
            }
        }
    }
}

/// Writes everything of a connect in one synced batch.
pub fn connect(
    rocks: &mut Db,
    new_tip: &ChainTip,
    entry: IndexEntry,
    locations: &[(TxId, TxEntry)],
    diff: &StateDiff,
) -> Result<(), StoreError> {
    let mut batch = WriteBatch::default();
    stage_diff(rocks, &mut batch, diff)?;
    let tx_index = family(&rocks.db, TX_INDEX)?;
    for (id, location) in locations {
        batch.put_cf(tx_index, id.0.0, location.as_bytes());
    }
    batch.put_cf(
        family(&rocks.db, UNDO)?,
        new_tip.id.0.0,
        borsh::to_vec(diff).map_err(StoreError::Encode)?,
    );
    batch.put_cf(
        family(&rocks.db, BLOCK_INDEX)?,
        new_tip.id.0.0,
        entry.as_bytes(),
    );
    batch.put_cf(
        family(&rocks.db, CANONICAL)?,
        new_tip.height.0.to_be_bytes(),
        new_tip.id.0.0,
    );
    let meta = family(&rocks.db, META)?;
    batch.put_cf(meta, KEY_TIP, new_tip.id.0.0);
    if new_tip.height == Height(0) {
        batch.put_cf(meta, KEY_GENESIS, new_tip.id.0.0);
    }
    commit(&rocks.db, batch, true)?;
    refresh_circuits(rocks, diff);
    Ok(())
}

/// Undoes a connect in one synced batch, from the `undo` row of the tip.
pub fn disconnect(
    rocks: &mut Db,
    tip: &BlockId,
    entry: IndexEntry,
    parent: &BlockId,
    txids: &[TxId],
) -> Result<(), StoreError> {
    let undo_bytes = get(&rocks.db, UNDO, &tip.0.0)?
        .ok_or_else(|| StoreError::Corrupt(format!("tip {tip} has no undo data")))?;
    let inverse = unborsh::<StateDiff>(&undo_bytes)?.inverse();
    let mut batch = WriteBatch::default();
    stage_diff(rocks, &mut batch, &inverse)?;
    let tx_index = family(&rocks.db, TX_INDEX)?;
    for id in txids {
        batch.delete_cf(tx_index, id.0.0);
    }
    batch.delete_cf(family(&rocks.db, UNDO)?, tip.0.0);
    batch.delete_cf(
        family(&rocks.db, CANONICAL)?,
        entry.height().0.to_be_bytes(),
    );
    batch.put_cf(family(&rocks.db, BLOCK_INDEX)?, tip.0.0, entry.as_bytes());
    batch.put_cf(family(&rocks.db, META)?, KEY_TIP, parent.0.0);
    commit(&rocks.db, batch, true)?;
    refresh_circuits(rocks, &inverse);
    Ok(())
}
