//! Header storage of the light node (pouw-node#102): only the block headers, never a
//! body or the state. The headers are one file of fixed-size records, so the header of
//! height `h` is at a known offset and an old header is read without a scan. The last N
//! headers are also kept in memory, which serves the tip and the recent heights without
//! touching the file.
//!
//! The first header stored is the anchor, the genesis block or a later checkpoint, and
//! each next header must extend the tip: parent id, chain id and height are checked.
//! The proof of work is not checked here, that belongs to the sync that feeds the store.
//!
//! # File format
//!
//! 8 bytes of magic `pwlhdr01`, then the headers in height order, each exactly
//! `size_of::<BlockHeader>()` bytes in the layout of `pouw_types::BlockHeader`. A header
//! is appended with one write and `fdatasync`. A last record cut short by a crash is
//! dropped when the file is opened, so the store continues from the last whole header.

use std::{
    collections::VecDeque,
    fs::{File, OpenOptions},
    io,
    os::unix::fs::FileExt,
    path::Path,
};

use pouw_types::{BlockHeader, BlockId, Height, block_id};
use thiserror::Error;
use tracing::warn;
use zerocopy::{FromBytes, IntoBytes};

const MAGIC: [u8; 8] = *b"pwlhdr01";
const MAGIC_LEN: u64 = 8;
const HEADER_LEN: usize = size_of::<BlockHeader>();
const RECORD: u64 = HEADER_LEN as u64;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("header file: {0}")]
    Io(#[from] io::Error),
    #[error("not a header file")]
    BadMagic,
    #[error("the header file is corrupt: {0}")]
    Corrupt(String),
    #[error("the parent is {found}, the tip is {expected}")]
    NotAChild { expected: BlockId, found: BlockId },
    #[error("height {found}, expected {expected}")]
    BadHeight { expected: u64, found: u64 },
    #[error("chain id {found}, the stored headers have {expected}")]
    ChainId { expected: u32, found: u32 },
}

#[derive(Debug)]
pub struct HeaderStore {
    file: File,
    /// Height of the first stored header, meaningful when `len > 0`.
    first: u64,
    /// Number of stored headers.
    len: u64,
    /// Most headers kept in `cache`, at least 1.
    capacity: usize,
    /// The last `capacity` headers with their ids, oldest first.
    cache: VecDeque<(BlockId, BlockHeader)>,
}

fn offset(index: u64) -> Result<u64, StoreError> {
    index
        .checked_mul(RECORD)
        .and_then(|bytes| bytes.checked_add(MAGIC_LEN))
        .ok_or_else(|| StoreError::Corrupt("a file offset overflows".to_owned()))
}

/// `next` must extend `previous`: its parent, chain id and height.
fn check_link(
    previous_id: &BlockId,
    previous: &BlockHeader,
    next: &BlockHeader,
) -> Result<(), StoreError> {
    if next.parent != *previous_id {
        return Err(StoreError::NotAChild {
            expected: *previous_id,
            found: next.parent,
        });
    }
    if next.chain_id.get() != previous.chain_id.get() {
        return Err(StoreError::ChainId {
            expected: previous.chain_id.get(),
            found: next.chain_id.get(),
        });
    }
    let expected = previous.height.get().saturating_add(1);
    if next.height.get() != expected {
        return Err(StoreError::BadHeight {
            expected,
            found: next.height.get(),
        });
    }
    Ok(())
}

impl HeaderStore {
    /// Opens the header file at `path`, creating it when it does not exist, and keeps
    /// the last `cache` headers in memory (at least one). A record cut short at the end
    /// of the file is dropped.
    ///
    /// # Errors
    ///
    /// [`StoreError::BadMagic`] for a file of another kind, [`StoreError::Corrupt`] when
    /// the cached tail of the file does not link, [`StoreError::Io`] otherwise.
    pub fn open(path: &Path, cache: usize) -> Result<Self, StoreError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let size = file.metadata()?.len();
        if size == 0 {
            file.write_all_at(&MAGIC, 0)?;
            file.sync_all()?;
        } else {
            let mut magic = [0_u8; 8];
            if size < MAGIC_LEN {
                return Err(StoreError::BadMagic);
            }
            file.read_exact_at(&mut magic, 0)?;
            if magic != MAGIC {
                return Err(StoreError::BadMagic);
            }
        }
        let body = file.metadata()?.len().saturating_sub(MAGIC_LEN);
        let len = body / RECORD;
        if body % RECORD != 0 {
            warn!(
                bytes = body % RECORD,
                "dropping a record cut short at the end of the header file"
            );
            file.set_len(offset(len)?)?;
            file.sync_all()?;
        }
        let mut store = Self {
            file,
            first: 0,
            len,
            capacity: cache.max(1),
            cache: VecDeque::new(),
        };
        if len > 0 {
            store.first = store.read_at(0)?.height.get();
            store.load_tail()?;
        }
        Ok(store)
    }

    /// Number of stored headers.
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Height of the first stored header, the anchor.
    pub fn first_height(&self) -> Option<Height> {
        (self.len > 0).then_some(Height(self.first))
    }

    /// Height and id of the last stored header, `None` while the store is empty.
    pub fn tip(&self) -> Option<(Height, BlockId)> {
        self.cache
            .back()
            .map(|(id, header)| (Height(header.height.get()), *id))
    }

    /// Headers in memory, at most the cache size given to [`HeaderStore::open`].
    pub fn cached(&self) -> usize {
        self.cache.len()
    }

    /// Appends `header`. The first header of an empty store is accepted as the anchor,
    /// every other one must extend the tip.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotAChild`], [`StoreError::ChainId`] or [`StoreError::BadHeight`]
    /// when it does not extend the tip, [`StoreError::Io`] when the write fails. After a
    /// failed write the store may hold a cut-short record, which the next open drops.
    pub fn push(&mut self, header: BlockHeader) -> Result<(), StoreError> {
        if let Some((tip_id, tip)) = self.cache.back() {
            check_link(tip_id, tip, &header)?;
        }
        let new_len = self
            .len
            .checked_add(1)
            .ok_or_else(|| StoreError::Corrupt("the header count overflows".to_owned()))?;
        self.file
            .write_all_at(header.as_bytes(), offset(self.len)?)?;
        self.file.sync_data()?;
        if self.len == 0 {
            self.first = header.height.get();
        }
        self.len = new_len;
        self.cache.push_back((block_id(&header), header));
        if self.cache.len() > self.capacity {
            self.cache.pop_front();
        }
        Ok(())
    }

    /// Removes the tip, for a reorganization, and returns it. `None` when empty.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when the file cannot be shortened or read.
    pub fn pop(&mut self) -> Result<Option<BlockHeader>, StoreError> {
        let Some(header) = self.cache.back().map(|(_, header)| *header) else {
            return Ok(None);
        };
        let new_len = self.len.saturating_sub(1);
        self.file.set_len(offset(new_len)?)?;
        self.file.sync_all()?;
        self.len = new_len;
        self.load_tail()?;
        Ok(Some(header))
    }

    /// The header at `height`, from memory when it is among the last N, else from the
    /// file. `None` outside the stored range.
    ///
    /// # Errors
    ///
    /// [`StoreError::Io`] when the file cannot be read.
    pub fn get(&self, height: Height) -> Result<Option<BlockHeader>, StoreError> {
        if self.len == 0 {
            return Ok(None);
        }
        let Some(index) = height.0.checked_sub(self.first) else {
            return Ok(None);
        };
        if index >= self.len {
            return Ok(None);
        }
        let cached = u64::try_from(self.cache.len()).unwrap_or(u64::MAX);
        let cached_from = self.len.saturating_sub(cached);
        if index >= cached_from {
            let position = usize::try_from(index.saturating_sub(cached_from)).unwrap_or(usize::MAX);
            return Ok(self.cache.get(position).map(|(_, header)| *header));
        }
        self.read_at(index).map(Some)
    }

    fn read_at(&self, index: u64) -> Result<BlockHeader, StoreError> {
        let mut bytes = [0_u8; HEADER_LEN];
        self.file.read_exact_at(&mut bytes, offset(index)?)?;
        BlockHeader::read_from_bytes(&bytes)
            .ok()
            .ok_or_else(|| StoreError::Corrupt(format!("record {index} is not a header")))
    }

    /// Fills the cache with the last `capacity` headers and checks that they link and
    /// that the tip has the height the count says.
    fn load_tail(&mut self) -> Result<(), StoreError> {
        self.cache.clear();
        let want = u64::try_from(self.capacity)
            .unwrap_or(u64::MAX)
            .min(self.len);
        let start = self.len.saturating_sub(want);
        for index in start..self.len {
            let header = self.read_at(index)?;
            if let Some((previous_id, previous)) = self.cache.back() {
                check_link(previous_id, previous, &header)
                    .map_err(|error| StoreError::Corrupt(format!("record {index}: {error}")))?;
            }
            self.cache.push_back((block_id(&header), header));
        }
        if let Some((_, tip)) = self.cache.back() {
            let expected = self.first.saturating_add(self.len.saturating_sub(1));
            if tip.height.get() != expected {
                return Err(StoreError::Corrupt(format!(
                    "the tip has height {}, the count says {expected}",
                    tip.height.get()
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
