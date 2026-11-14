//! Persistent storage of blocks, the chain state and the indexes the API reads. The
//! store knows no rule except the shape of its own tables ([`schema`]): the caller
//! validates a block and computes its [`StateDiff`], the store writes them in one atomic
//! step and can undo the last one. A block is kept as the bytes it was received in, and
//! those bytes are what is read back.
//!
//! Headers come before bodies. The block path, in the order of the calls:
//!
//! 1. [`put_header`] indexes a header whose parent is indexed, with its height and
//!    cumulative work, so a header can be stored (headers-first sync) before its body;
//! 2. [`put_body`] stores the received bytes of an indexed header;
//! 3. [`mark_work_valid`] records that the work of the block is verified;
//! 4. [`connect_block`] makes the block the tip, and [`disconnect_tip`] undoes it.
//!
//! [`mark_failed`] flags a block that broke a rule, see [`schema::Status`].
//!
//! [`Store`] is one concrete type. Writes are free functions taking `&mut Store`,
//! reads go through a [`Reader`] made by [`read`] and hand out borrows of the stored
//! bytes. Each backend is behind its own feature and the one to run is chosen by
//! [`StoreKind`] when the store is opened. Every write is atomic: after an error the
//! store is unchanged.
//!
//! Every read returns `Result<Option<_>, StoreError>`: `Ok(None)` is a block, height or
//! transaction the store does not hold, `Err` is a backend fault or a record that does
//! not decode. The caller never treats an `Err` as absence.

#[cfg(feature = "store-mem")]
mod mem;
#[cfg(feature = "rocksdb")]
pub mod rocks;
pub mod schema;

#[cfg(not(any(feature = "store-mem", feature = "rocksdb")))]
compile_error!("enable the `store-mem` or the `rocksdb` feature to have a store backend");

use std::{borrow::Cow, path::Path};

use pouw_consensus::{ChainTip, DiffMismatch, StateDiff, StateError, StateView};
use pouw_crypto::Address;
use pouw_types::{
    Account, Block, BlockHeader, BlockId, CircuitEntry, CircuitId, CumWork, HeaderError, Height,
    TxId, U32, UsageCounter, block_work,
};
use thiserror::Error;
use zerocopy::IntoBytes;

use crate::config::StoreKind;
use schema::{IndexEntry, SCHEMA_VERSION, Status, TxEntry};

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("block {0} is not stored")]
    UnknownBlock(BlockId),
    /// The block does not extend the current tip.
    #[error("block {block} does not extend the tip {tip:?}")]
    NotChildOfTip {
        /// The block given.
        block: BlockId,
        /// The tip, `None` before genesis.
        tip: Option<BlockId>,
    },
    /// The parent of a header is not indexed, so the header is an orphan.
    #[error("header {block} is an orphan: its parent {parent} is not indexed")]
    Orphan {
        /// The header given.
        block: BlockId,
        /// Its parent, which the store does not know.
        parent: BlockId,
    },
    /// The height of a header is not its parent height plus one (0 for genesis).
    #[error("header {block} has height {found}, its parent gives {expected}")]
    HeightMismatch {
        /// The header given.
        block: BlockId,
        /// Parent height plus one.
        expected: u64,
        /// `header.height`.
        found: u64,
    },
    /// The parent is at the last representable height, so no child height exists.
    #[error("block {0} is at the last height and cannot have a child")]
    HeightOverflow(BlockId),
    /// A body arrived for a block whose header is not stored.
    #[error("block {0} has no stored header, so its body is refused")]
    NoHeader(BlockId),
    /// The first bytes of a body are not the stored header of the same id.
    #[error("the body of block {0} does not start with its stored header")]
    BodyHeaderMismatch(BlockId),
    /// The block is indexed but its body is not stored.
    #[error("block {0} has no stored body")]
    NoBody(BlockId),
    /// The block, or an ancestor of it, failed validation.
    #[error("block {0} is failed and is never connected")]
    Failed(BlockId),
    /// The cumulative work of a header does not fit 256 bits.
    #[error("cumulative work of block {0} overflows")]
    WorkOverflow(BlockId),
    /// The store was written with another layout of its tables.
    #[error(
        "the store has schema version {found}, this node reads version {expected}: \
         remove the data directory or run the matching node version"
    )]
    SchemaMismatch {
        /// Version found in the store.
        found: u32,
        /// [`SCHEMA_VERSION`].
        expected: u32,
    },
    #[error("the chain is empty")]
    EmptyChain,
    #[error("the genesis block cannot be disconnected")]
    GenesisDisconnect,
    #[error(transparent)]
    Diff(#[from] DiffMismatch),
    #[error(transparent)]
    State(#[from] StateError),
    #[error("corrupt store: {0}")]
    Corrupt(String),
    #[error("cannot encode a block: {0}")]
    Encode(borsh::io::Error),
    #[error("cannot decode a stored block: {0}")]
    Decode(borsh::io::Error),
    /// The stored bytes of a block do not start with a header of a known layout.
    #[error("a stored block has a bad header: {0}")]
    Header(#[from] HeaderError),
    /// A block holds more leaves than a leaf index can count.
    #[error("block {block} has too many leaves: {source}")]
    TooManyLeaves {
        block: BlockId,
        source: std::num::TryFromIntError,
    },
    /// The backend is not built into this binary.
    #[error("the {kind:?} store needs the `{feature}` feature, which is off")]
    FeatureOff {
        kind: StoreKind,
        feature: &'static str,
    },
    /// The database of the `RocksDB` backend failed.
    #[error("the RocksDB database failed: {0}")]
    Backend(String),
}

/// Where a canonical block holds a transaction. For a proof request this is its proof
/// tx, and `index` is the Merkle leaf index of the proof tx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxLocation {
    /// The including block.
    pub block: BlockId,
    pub height: Height,
    /// Leaf index in its Merkle tree.
    pub index: u32,
}

/// Blocks, state and indexes of one chain, held by the backend that [`open`] chose.
#[derive(Debug)]
pub enum Store {
    #[cfg(feature = "store-mem")]
    Mem(Box<mem::Mem>),
    #[cfg(feature = "rocksdb")]
    Rocks(rocks::Db),
}

/// A consistent read view of a [`Store`] made by [`read`]. Its chain state is the state
/// at the tip, served through [`StateView`]. The store cannot be written while a
/// reader lives.
#[derive(Debug, Clone, Copy)]
pub enum Reader<'a> {
    #[cfg(feature = "store-mem")]
    Mem(&'a mem::Mem),
    #[cfg(feature = "rocksdb")]
    Rocks(&'a rocks::Db),
}

/// A stored block as encoded bytes, with its header read from them. The bytes are
/// borrowed from the memory backend and owned when a database returned them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockBytes<'a> {
    pub header: BlockHeader,
    /// The whole block in its borsh encoding, which starts with the header bytes.
    pub bytes: Cow<'a, [u8]>,
}

/// Opens or creates the store of `kind` under `path` and checks its schema version. The
/// memory backend ignores `path`.
pub fn open(kind: StoreKind, path: &Path) -> Result<Store, StoreError> {
    let store = open_backend(kind, path)?;
    check_schema(&store)?;
    Ok(store)
}

/// Fails with [`StoreError::SchemaMismatch`] when the store was written with a
/// [`SCHEMA_VERSION`] other than this build's.
pub fn check_schema(store: &Store) -> Result<(), StoreError> {
    let found = match store {
        #[cfg(feature = "store-mem")]
        Store::Mem(mem) => mem::schema_version(mem),
        #[cfg(feature = "rocksdb")]
        Store::Rocks(db) => rocks::schema_version(db)?,
    };
    if found == SCHEMA_VERSION {
        Ok(())
    } else {
        Err(StoreError::SchemaMismatch {
            found,
            expected: SCHEMA_VERSION,
        })
    }
}

fn open_backend(kind: StoreKind, path: &Path) -> Result<Store, StoreError> {
    match kind {
        #[cfg(feature = "store-mem")]
        StoreKind::Memory => Ok(memory()),
        #[cfg(feature = "rocksdb")]
        StoreKind::Rocksdb => rocks::open(path).map(Store::Rocks),
        #[allow(
            unreachable_patterns,
            reason = "every kind is built in with all features"
        )]
        kind => {
            _ = path;
            Err(StoreError::FeatureOff {
                kind,
                feature: kind.feature(),
            })
        }
    }
}

/// An empty store in memory.
#[cfg(feature = "store-mem")]
pub fn memory() -> Store {
    Store::Mem(Box::default())
}

/// A read view of the store as it is now.
pub fn read(store: &Store) -> Result<Reader<'_>, StoreError> {
    Ok(match store {
        #[cfg(feature = "store-mem")]
        Store::Mem(mem) => Reader::Mem(mem),
        #[cfg(feature = "rocksdb")]
        Store::Rocks(db) => Reader::Rocks(db),
    })
}

/// The canonical tip, `None` before genesis is connected.
pub fn tip(reader: &Reader<'_>) -> Result<Option<ChainTip>, StoreError> {
    match reader {
        #[cfg(feature = "store-mem")]
        Reader::Mem(view) => mem::tip(view),
        #[cfg(feature = "rocksdb")]
        Reader::Rocks(view) => rocks::tip(view),
    }
}

/// The index entry of a block whose header is stored: height, cumulative work and
/// status.
pub fn index(reader: &Reader<'_>, id: &BlockId) -> Result<Option<IndexEntry>, StoreError> {
    match reader {
        #[cfg(feature = "store-mem")]
        Reader::Mem(view) => Ok(mem::index(view, id)),
        #[cfg(feature = "rocksdb")]
        Reader::Rocks(view) => rocks::index(view, id),
    }
}

/// Header of a stored block, canonical or not, with or without its body.
pub fn header<'r>(
    reader: &'r Reader<'_>,
    id: &BlockId,
) -> Result<Option<&'r BlockHeader>, StoreError> {
    match reader {
        #[cfg(feature = "store-mem")]
        Reader::Mem(view) => Ok(mem::header(view, id)),
        #[cfg(feature = "rocksdb")]
        Reader::Rocks(view) => rocks::header(view, id),
    }
}

/// A stored block, canonical or not. `None` while only its header is stored.
pub fn block<'r>(
    reader: &'r Reader<'_>,
    id: &BlockId,
) -> Result<Option<BlockBytes<'r>>, StoreError> {
    stored_block(reader, id)?.map(parse_block).transpose()
}

/// Hash of the canonical block at `height`.
pub fn canonical_id(reader: &Reader<'_>, height: Height) -> Result<Option<BlockId>, StoreError> {
    match reader {
        #[cfg(feature = "store-mem")]
        Reader::Mem(view) => Ok(mem::canonical_id(view, height)),
        #[cfg(feature = "rocksdb")]
        Reader::Rocks(view) => rocks::canonical_id(view, height),
    }
}

/// Location of a transaction in the canonical chain.
pub fn tx_location(reader: &Reader<'_>, id: &TxId) -> Result<Option<TxLocation>, StoreError> {
    match reader {
        #[cfg(feature = "store-mem")]
        Reader::Mem(view) => mem::tx_location(view, id),
        #[cfg(feature = "rocksdb")]
        Reader::Rocks(view) => rocks::tx_location(view, id),
    }
}

/// The owned block of `stored`.
pub fn decode(stored: &BlockBytes<'_>) -> Result<Block, StoreError> {
    borsh::from_slice(&stored.bytes).map_err(StoreError::Decode)
}

/// Indexes the header `header` of block `id`, whose parent must be indexed already.
/// The entry gets `height = header.height`, `work = parent work + block_work(target)`
/// (the work of the block alone for a genesis header, whose parent is
/// [`BlockId::ZERO`]), [`Status::HEADER_VALID`], and [`Status::FAILED`] when the parent
/// is failed. A header that is indexed already is left as it is and its entry returned.
///
/// An unknown parent is [`StoreError::Orphan`] and a height that is not the parent
/// height plus one is [`StoreError::HeightMismatch`]. A parent at `u64::MAX` is
/// [`StoreError::HeightOverflow`]. The store is unchanged then.
pub fn put_header(
    store: &mut Store,
    id: &BlockId,
    header: &BlockHeader,
) -> Result<IndexEntry, StoreError> {
    let entry = {
        let reader = read(store)?;
        if let Some(known) = index(&reader, id)? {
            return Ok(known);
        }
        let found = header.height.get();
        let (expected, parent_work, parent_status) = if header.parent == BlockId::ZERO {
            (0, CumWork::ZERO, Status::NONE)
        } else {
            let parent = index(&reader, &header.parent)?.ok_or(StoreError::Orphan {
                block: *id,
                parent: header.parent,
            })?;
            let expected = parent
                .height
                .get()
                .checked_add(1)
                .ok_or(StoreError::HeightOverflow(header.parent))?;
            (expected, parent.work(), parent.status)
        };
        if found != expected {
            return Err(StoreError::HeightMismatch {
                block: *id,
                expected,
                found,
            });
        }
        let work = parent_work
            .checked_add(block_work(&header.target))
            .ok_or(StoreError::WorkOverflow(*id))?;
        let inherited = parent_status.contains(Status::FAILED);
        let status = if inherited {
            Status::HEADER_VALID.with(Status::FAILED)
        } else {
            Status::HEADER_VALID
        };
        IndexEntry::new(Height(found), work, status)
    };
    match store {
        #[cfg(feature = "store-mem")]
        Store::Mem(mem) => mem::insert_header(mem, *id, *header, entry),
        #[cfg(feature = "rocksdb")]
        Store::Rocks(db) => rocks::insert_header(db, *id, *header, entry)?,
    }
    Ok(entry)
}

/// Keeps the received `bytes` of block `id` as they are and sets
/// [`Status::BODY_STORED`]. The header of `id` must be stored
/// ([`StoreError::NoHeader`]) and `bytes` must start with it
/// ([`StoreError::BodyHeaderMismatch`]). Storing a body twice is not an error.
pub fn put_body(store: &mut Store, id: &BlockId, bytes: &[u8]) -> Result<(), StoreError> {
    let entry = {
        let reader = read(store)?;
        let stored = header(&reader, id)?.ok_or(StoreError::NoHeader(*id))?;
        if bytes.get(..BlockHeader::SIZE) != Some(stored.as_bytes()) {
            return Err(StoreError::BodyHeaderMismatch(*id));
        }
        let entry = index(&reader, id)?.ok_or(StoreError::NoHeader(*id))?;
        IndexEntry {
            status: entry.status.with(Status::BODY_STORED),
            ..entry
        }
    };
    match store {
        #[cfg(feature = "store-mem")]
        Store::Mem(mem) => mem::insert_body(mem, *id, bytes, entry),
        #[cfg(feature = "rocksdb")]
        Store::Rocks(db) => rocks::insert_body(db, *id, bytes, entry)?,
    }
    Ok(())
}

/// Sets [`Status::WORK_VALID`] on the indexed block `id`: its work is verified.
pub fn mark_work_valid(store: &mut Store, id: &BlockId) -> Result<(), StoreError> {
    set_status(store, id, Status::WORK_VALID)
}

/// Sets [`Status::FAILED`] on the indexed block `id`: it broke a rule. No later
/// [`connect_block`] accepts it, and the headers stored after it as its descendants are
/// failed on arrival.
pub fn mark_failed(store: &mut Store, id: &BlockId) -> Result<(), StoreError> {
    set_status(store, id, Status::FAILED)
}

fn set_status(store: &mut Store, id: &BlockId, flag: Status) -> Result<(), StoreError> {
    let entry = index(&read(store)?, id)?.ok_or(StoreError::UnknownBlock(*id))?;
    let entry = IndexEntry {
        status: entry.status.with(flag),
        ..entry
    };
    match store {
        #[cfg(feature = "store-mem")]
        Store::Mem(mem) => mem::set_index(mem, *id, entry),
        #[cfg(feature = "rocksdb")]
        Store::Rocks(db) => rocks::set_index(db, *id, entry)?,
    }
    Ok(())
}

/// Makes the stored block `id`, a child of the tip, the new tip: applies `diff` to
/// the state, indexes its transactions and sets [`Status::CONNECTED`], all in one
/// atomic write. The genesis block is connected the same way on an empty chain. `txids`
/// are the ids of the block in the order of `Block::txids_into`, and the position of an
/// id is its index in the block. The cumulative work of the new tip is the one
/// [`put_header`] stored.
///
/// Refused: a block without an index entry ([`StoreError::UnknownBlock`]), a failed
/// one ([`StoreError::Failed`]), one without a body ([`StoreError::NoBody`]), and one
/// that does not extend the tip ([`StoreError::NotChildOfTip`]).
pub fn connect_block(
    store: &mut Store,
    id: &BlockId,
    txids: &[TxId],
    diff: &StateDiff,
) -> Result<ChainTip, StoreError> {
    let (new_tip, entry, locations) = {
        let reader = read(store)?;
        let entry = index(&reader, id)?.ok_or(StoreError::UnknownBlock(*id))?;
        if entry.status.contains(Status::FAILED) {
            return Err(StoreError::Failed(*id));
        }
        let stored = block(&reader, id)?.ok_or(StoreError::NoBody(*id))?;
        let tip = tip(&reader)?;
        let extends = match &tip {
            Some(tip) => stored.header.parent == tip.id,
            None => stored.header.parent == BlockId::ZERO && stored.header.height.get() == 0,
        };
        if !extends {
            return Err(StoreError::NotChildOfTip {
                block: *id,
                tip: tip.map(|t| t.id),
            });
        }
        let new_tip = ChainTip {
            id: *id,
            height: entry.height(),
            cumulative_work: entry.work(),
        };
        let entry = IndexEntry {
            status: entry.status.with(Status::CONNECTED),
            ..entry
        };
        (new_tip, entry, located(txids, *id)?)
    };
    match store {
        #[cfg(feature = "store-mem")]
        Store::Mem(mem) => mem::connect(mem, &new_tip, entry, locations, diff)?,
        #[cfg(feature = "rocksdb")]
        Store::Rocks(db) => rocks::connect(db, &new_tip, entry, &locations, diff)?,
    }
    Ok(new_tip)
}

/// Undoes the last [`connect_block`], clears [`Status::CONNECTED`] and returns the new
/// tip. The block stays stored. `txids` are the ids of the tip block, as given to
/// [`connect_block`].
pub fn disconnect_tip(store: &mut Store, txids: &[TxId]) -> Result<ChainTip, StoreError> {
    let (tip, entry, parent) = {
        let reader = read(store)?;
        let tip = tip(&reader)?.ok_or(StoreError::EmptyChain)?;
        let parent = parent_of_tip(&reader)?.ok_or(StoreError::GenesisDisconnect)?;
        let entry = index(&reader, &tip.id)?.ok_or(StoreError::UnknownBlock(tip.id))?;
        let entry = IndexEntry {
            status: entry.status.without(Status::CONNECTED),
            ..entry
        };
        (tip, entry, parent)
    };
    match store {
        #[cfg(feature = "store-mem")]
        Store::Mem(mem) => mem::disconnect(mem, &tip.id, entry, &parent.id, txids)?,
        #[cfg(feature = "rocksdb")]
        Store::Rocks(db) => rocks::disconnect(db, &tip.id, entry, &parent.id, txids)?,
    }
    Ok(parent)
}

impl StateView for Reader<'_> {
    fn account(&self, address: &Address) -> Result<Option<Account>, StateError> {
        match *self {
            #[cfg(feature = "store-mem")]
            Reader::Mem(view) => mem::account(view, address),
            #[cfg(feature = "rocksdb")]
            Reader::Rocks(view) => rocks::account(view, address),
        }
    }

    fn circuit(&self, id: &CircuitId) -> Result<Option<&CircuitEntry>, StateError> {
        match *self {
            #[cfg(feature = "store-mem")]
            Reader::Mem(view) => mem::circuit(view, id),
            #[cfg(feature = "rocksdb")]
            Reader::Rocks(view) => rocks::circuit(view, id),
        }
    }

    fn usage_counter(
        &self,
        miner: &Address,
        circuit: &CircuitId,
    ) -> Result<Option<UsageCounter>, StateError> {
        match *self {
            #[cfg(feature = "store-mem")]
            Reader::Mem(view) => mem::usage_counter(view, miner, circuit),
            #[cfg(feature = "rocksdb")]
            Reader::Rocks(view) => rocks::usage_counter(view, miner, circuit),
        }
    }
}

fn parent_of_tip(reader: &Reader<'_>) -> Result<Option<ChainTip>, StoreError> {
    match reader {
        #[cfg(feature = "store-mem")]
        Reader::Mem(view) => mem::parent_of_tip(view),
        #[cfg(feature = "rocksdb")]
        Reader::Rocks(view) => rocks::parent_of_tip(view),
    }
}

fn stored_block<'r>(
    reader: &'r Reader<'_>,
    id: &BlockId,
) -> Result<Option<Cow<'r, [u8]>>, StoreError> {
    match reader {
        #[cfg(feature = "store-mem")]
        Reader::Mem(view) => Ok(mem::stored_block(view, id).map(Cow::Borrowed)),
        #[cfg(feature = "rocksdb")]
        Reader::Rocks(view) => rocks::stored_block(view, id),
    }
}

fn parse_block(bytes: Cow<'_, [u8]>) -> Result<BlockBytes<'_>, StoreError> {
    let prefix = bytes.get(..BlockHeader::SIZE).unwrap_or(&bytes[..]);
    let header = *BlockHeader::ref_from_versioned(prefix)?;
    Ok(BlockBytes { header, bytes })
}

fn located(txids: &[TxId], block: BlockId) -> Result<Vec<(TxId, TxEntry)>, StoreError> {
    txids
        .iter()
        .enumerate()
        .map(|(index, id)| {
            let index = u32::try_from(index)
                .map_err(|source| StoreError::TooManyLeaves { block, source })?;
            Ok((
                *id,
                TxEntry {
                    block,
                    index: U32::new(index),
                },
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests;
