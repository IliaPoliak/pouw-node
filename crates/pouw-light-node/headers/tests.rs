use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

use pouw_crypto::{Address, Hash32};
use pouw_types::{BlockHeader, BlockId, Height, Target, U32, U64, block_id};
use zerocopy::IntoBytes;

use super::{HeaderStore, MAGIC, StoreError};

fn header(height: u64, parent: BlockId, nonce: u64) -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(7),
        system_id: U64::new(0),
        height: U64::new(height),
        parent,
        timestamp: U64::new(1_000),
        miner: Address([0; 32]),
        tx_root: Hash32::ZERO,
        target: Target([0xff; 32]),
        nonce: U64::new(nonce),
    }
}

/// `count` linked headers from the genesis block.
fn chain(count: u64) -> Vec<BlockHeader> {
    let mut headers = Vec::new();
    let mut parent = BlockId::ZERO;
    for height in 0..count {
        let next = header(height, parent, 0);
        parent = block_id(&next);
        headers.push(next);
    }
    headers
}

fn path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pouw-light-{}-{name}.bin", std::process::id()));
    drop(fs::remove_file(&path));
    path
}

fn push_all(store: &mut HeaderStore, headers: &[BlockHeader]) {
    for next in headers {
        store.push(*next).unwrap();
    }
}

#[test]
fn an_empty_store_has_no_tip() {
    let store = HeaderStore::open(&path("empty"), 4).unwrap();
    assert!(store.is_empty());
    assert_eq!(store.tip(), None);
    assert_eq!(store.get(Height(0)).unwrap(), None);
}

#[test]
fn pushed_headers_are_read_back_by_height() {
    let headers = chain(5);
    let mut store = HeaderStore::open(&path("read"), 8).unwrap();
    push_all(&mut store, &headers);
    assert_eq!(store.len(), 5);
    for (height, expected) in (0..).zip(&headers) {
        assert_eq!(store.get(Height(height)).unwrap(), Some(*expected));
    }
    assert_eq!(store.get(Height(5)).unwrap(), None);
    assert_eq!(store.tip(), Some((Height(4), block_id(&headers[4]))));
}

#[test]
fn a_header_that_does_not_extend_the_tip_is_refused() {
    let headers = chain(4);
    let mut store = HeaderStore::open(&path("link"), 8).unwrap();
    push_all(&mut store, &headers[..2]);
    assert!(matches!(
        store.push(headers[3]),
        Err(StoreError::NotAChild { .. })
    ));
    let mut wrong_height = headers[2];
    wrong_height.height = U64::new(5);
    assert!(matches!(
        store.push(wrong_height),
        Err(StoreError::BadHeight {
            expected: 2,
            found: 5
        })
    ));
    let mut wrong_chain = headers[2];
    wrong_chain.chain_id = U32::new(8);
    assert!(matches!(
        store.push(wrong_chain),
        Err(StoreError::ChainId {
            expected: 7,
            found: 8
        })
    ));
    assert_eq!(store.len(), 2);
}

#[test]
fn after_a_restart_the_store_continues_from_the_last_header() {
    let headers = chain(4);
    let file = path("restart");
    let mut store = HeaderStore::open(&file, 8).unwrap();
    push_all(&mut store, &headers[..3]);
    drop(store);

    let mut store = HeaderStore::open(&file, 8).unwrap();
    assert_eq!(store.len(), 3);
    assert_eq!(store.tip(), Some((Height(2), block_id(&headers[2]))));
    store.push(headers[3]).unwrap();
    assert_eq!(store.tip(), Some((Height(3), block_id(&headers[3]))));
    assert_eq!(store.get(Height(0)).unwrap(), Some(headers[0]));
}

#[test]
fn only_the_last_n_headers_are_cached_and_older_ones_come_from_the_file() {
    let headers = chain(6);
    let file = path("cache");
    let mut store = HeaderStore::open(&file, 2).unwrap();
    push_all(&mut store, &headers);
    assert_eq!(store.cached(), 2);
    assert_eq!(store.get(Height(0)).unwrap(), Some(headers[0]));
    assert_eq!(store.get(Height(3)).unwrap(), Some(headers[3]));
    assert_eq!(store.get(Height(5)).unwrap(), Some(headers[5]));
    drop(store);

    let store = HeaderStore::open(&file, 3).unwrap();
    assert_eq!(store.cached(), 3);
    assert_eq!(store.tip(), Some((Height(5), block_id(&headers[5]))));
}

#[test]
fn the_first_header_can_be_a_checkpoint() {
    let headers = chain(5);
    let mut store = HeaderStore::open(&path("anchor"), 8).unwrap();
    push_all(&mut store, &headers[3..]);
    assert_eq!(store.first_height(), Some(Height(3)));
    assert_eq!(store.get(Height(2)).unwrap(), None);
    assert_eq!(store.get(Height(3)).unwrap(), Some(headers[3]));
    assert_eq!(store.tip(), Some((Height(4), block_id(&headers[4]))));
}

#[test]
fn pop_removes_the_tip_so_another_branch_can_follow() {
    let headers = chain(4);
    let file = path("pop");
    let mut store = HeaderStore::open(&file, 8).unwrap();
    push_all(&mut store, &headers);
    assert_eq!(store.pop().unwrap(), Some(headers[3]));
    assert_eq!(store.tip(), Some((Height(2), block_id(&headers[2]))));
    let other = header(3, block_id(&headers[2]), 99);
    store.push(other).unwrap();
    drop(store);

    let store = HeaderStore::open(&file, 8).unwrap();
    assert_eq!(store.len(), 4);
    assert_eq!(store.tip(), Some((Height(3), block_id(&other))));
}

#[test]
fn popping_every_header_empties_the_store() {
    let mut store = HeaderStore::open(&path("pop-all"), 1).unwrap();
    assert_eq!(store.pop().unwrap(), None);
    push_all(&mut store, &chain(2));
    assert!(store.pop().unwrap().is_some());
    assert!(store.pop().unwrap().is_some());
    assert_eq!(store.pop().unwrap(), None);
    assert_eq!(store.tip(), None);
}

#[test]
fn a_record_cut_short_by_a_crash_is_dropped_on_open() {
    let headers = chain(3);
    let file = path("partial");
    let mut store = HeaderStore::open(&file, 8).unwrap();
    push_all(&mut store, &headers);
    drop(store);
    let size = fs::metadata(&file).unwrap().len();
    let mut open = OpenOptions::new().append(true).open(&file).unwrap();
    open.write_all(&[0xab; 10]).unwrap();
    drop(open);

    let mut store = HeaderStore::open(&file, 8).unwrap();
    assert_eq!(store.len(), 3);
    assert_eq!(fs::metadata(&file).unwrap().len(), size);
    store.push(chain(4)[3]).unwrap();
}

#[test]
fn a_file_whose_tail_does_not_link_is_corrupt() {
    let headers = chain(3);
    let file = path("broken");
    let mut bytes = MAGIC.to_vec();
    bytes.extend_from_slice(headers[0].as_bytes());
    bytes.extend_from_slice(headers[2].as_bytes());
    fs::write(&file, bytes).unwrap();
    assert!(matches!(
        HeaderStore::open(&file, 8),
        Err(StoreError::Corrupt(_))
    ));
}

#[test]
fn a_file_of_another_kind_is_refused() {
    let file = path("magic");
    fs::write(&file, b"this is not a header file").unwrap();
    assert!(matches!(
        HeaderStore::open(&file, 8),
        Err(StoreError::BadMagic)
    ));
}
