use std::{fs, path::PathBuf};

use pouw_consensus::{ConsensusParams, InvalidBlock, PowError};
use pouw_crypto::{Address, Hash32};
use pouw_types::{
    Amount, BlockHeader, BlockId, ChainId, Height, Target, Timestamp, U32, U64, block_id,
};

use super::{VerifyError, accept, verify};
use crate::headers::HeaderStore;

const EASY: Target = Target([0xff; 32]);
const GENESIS_TIME: u64 = 1_000;
const NOW: Timestamp = Timestamp(10_000);

fn hard() -> Target {
    let mut bytes = [0_u8; 32];
    bytes[31] = 1;
    Target(bytes)
}

fn params(target: Target) -> ConsensusParams {
    ConsensusParams {
        chain_id: ChainId(7),
        initial_subsidy: Amount(50),
        halving_interval: 100,
        target_block_secs: 10,
        half_life_secs: 3600,
        initial_target: target,
        pow_limit: target,
        max_future_secs: 60,
        fee_per_public_input: Amount(1),
        fee_per_witness_kib: Amount(1),
    }
}

fn header(height: u64, parent: BlockId, timestamp: u64, target: Target) -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(7),
        system_id: U64::new(0),
        height: U64::new(height),
        parent,
        timestamp: U64::new(timestamp),
        miner: Address([0; 32]),
        tx_root: Hash32::ZERO,
        target,
        nonce: U64::new(0),
    }
}

/// The child of `parent` that arrives exactly on the schedule of 10 seconds a block, so
/// its target is that of `parent`.
fn child_of(parent: &BlockHeader) -> BlockHeader {
    let height = parent.height.get().saturating_add(1);
    let timestamp = GENESIS_TIME.saturating_add(height.saturating_mul(10));
    header(height, block_id(parent), timestamp, parent.target)
}

fn path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pouw-verify-{}-{name}.bin", std::process::id()));
    drop(fs::remove_file(&path));
    path
}

fn with_genesis(name: &str, target: Target) -> (HeaderStore, BlockHeader) {
    let mut store = HeaderStore::open(&path(name), 32).unwrap();
    let genesis = header(0, BlockId::ZERO, GENESIS_TIME, target);
    store.push(genesis).unwrap();
    (store, genesis)
}

#[test]
fn a_chain_of_on_schedule_headers_is_accepted_one_by_one() {
    let params = params(EASY);
    let (mut store, genesis) = with_genesis("chain", EASY);
    let mut parent = genesis;
    for _ in 0..30 {
        let next = child_of(&parent);
        accept(&mut store, &params, NOW, next).unwrap();
        parent = next;
    }
    assert_eq!(store.tip(), Some((Height(30), block_id(&parent))));
}

#[test]
fn a_header_with_a_wrong_link_is_refused_and_not_stored() {
    let params = params(EASY);
    let (mut store, genesis) = with_genesis("link", EASY);

    let mut bad = child_of(&genesis);
    bad.parent = BlockId(Hash32([9; 32]));
    let error = accept(&mut store, &params, NOW, bad).unwrap_err();
    assert!(matches!(
        error,
        VerifyError::Header(InvalidBlock::BadParent)
    ));

    let mut bad = child_of(&genesis);
    bad.height = U64::new(5);
    let error = verify(&store, &params, NOW, &bad).unwrap_err();
    assert!(matches!(
        error,
        VerifyError::Header(InvalidBlock::BadHeight { .. })
    ));

    let mut bad = child_of(&genesis);
    bad.chain_id = U32::new(8);
    let error = verify(&store, &params, NOW, &bad).unwrap_err();
    assert!(matches!(
        error,
        VerifyError::Header(InvalidBlock::BadChainId { .. })
    ));
    assert_eq!(store.len(), 1);
}

#[test]
fn a_header_with_a_target_off_the_schedule_is_refused() {
    let params = params(EASY);
    let (store, genesis) = with_genesis("target", EASY);
    let mut bad = child_of(&genesis);
    bad.target = Target([0xfe; 32]);
    let error = verify(&store, &params, NOW, &bad).unwrap_err();
    assert!(matches!(
        error,
        VerifyError::Header(InvalidBlock::BadTarget { .. })
    ));
}

#[test]
fn the_timestamp_must_be_above_the_median_and_not_far_ahead_of_the_clock() {
    let params = params(EASY);
    let (store, genesis) = with_genesis("time", EASY);

    let mut late = child_of(&genesis);
    late.timestamp = U64::new(GENESIS_TIME);
    let error = verify(&store, &params, NOW, &late).unwrap_err();
    assert!(matches!(error, VerifyError::Header(_)));

    let mut early = child_of(&genesis);
    early.timestamp = U64::new(NOW.0.saturating_add(61));
    let error = verify(&store, &params, NOW, &early).unwrap_err();
    assert!(matches!(error, VerifyError::Header(_)));

    verify(&store, &params, NOW, &child_of(&genesis)).unwrap();
}

#[test]
fn a_header_over_its_target_fails_the_proof_of_work() {
    let params = params(hard());
    let (mut store, genesis) = with_genesis("pow", hard());
    let next = child_of(&genesis);
    let error = accept(&mut store, &params, NOW, next).unwrap_err();
    assert!(matches!(
        error,
        VerifyError::Pow(PowError::AboveTarget { .. })
    ));
    assert_eq!(store.len(), 1);
}

#[test]
fn a_store_without_genesis_cannot_verify() {
    let params = params(EASY);
    let mut store = HeaderStore::open(&path("empty"), 4).unwrap();
    let anchor = header(5, BlockId::ZERO, GENESIS_TIME, EASY);
    let error = verify(&store, &params, NOW, &child_of(&anchor)).unwrap_err();
    assert!(matches!(error, VerifyError::EmptyStore));

    store.push(anchor).unwrap();
    let error = verify(&store, &params, NOW, &child_of(&anchor)).unwrap_err();
    assert!(matches!(error, VerifyError::NoGenesis(5)));
}
