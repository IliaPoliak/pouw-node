use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, RwLock},
    thread,
};

use pouw_api::view::{HeaderView, HeadersPage};
use pouw_consensus::ConsensusParams;
use pouw_crypto::{Address, Hash32};
use pouw_types::{
    Amount, BlockHeader, BlockId, ChainId, Height, Target, Timestamp, U32, U64, block_id,
};

use super::{HeaderSync, Outcome, SpecLoadError, SyncError, load_chain};
use crate::{
    headers::HeaderStore,
    upstream::{
        Upstream,
        tests::{dead_node, http},
    },
    verify::VerifyError,
};

const EASY: Target = Target([0xff; 32]);
const GENESIS_TIME: u64 = 1_000;
/// Far enough ahead of every header of the tests, which are on a schedule of 10 seconds a
/// block.
const NOW: Timestamp = Timestamp(100_000);

fn params() -> ConsensusParams {
    ConsensusParams {
        chain_id: ChainId(7),
        initial_subsidy: Amount(50),
        halving_interval: 100,
        target_block_secs: 10,
        half_life_secs: 3600,
        initial_target: EASY,
        pow_limit: EASY,
        max_future_secs: 60,
        fee_per_public_input: Amount(1),
        fee_per_witness_kib: Amount(1),
    }
}

fn genesis_with(miner: u8) -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(7),
        system_id: U64::new(0),
        height: U64::new(0),
        parent: BlockId::ZERO,
        timestamp: U64::new(GENESIS_TIME),
        miner: Address([miner; 32]),
        tx_root: Hash32::ZERO,
        target: EASY,
        nonce: U64::new(0),
    }
}

/// The child of `parent` that arrives exactly on the schedule, so its target is that of
/// `parent`. The `nonce` tells the branches of a fork apart.
fn child(parent: &BlockHeader, nonce: u64) -> BlockHeader {
    let height = parent.height.get().saturating_add(1);
    BlockHeader {
        height: U64::new(height),
        parent: block_id(parent),
        timestamp: U64::new(GENESIS_TIME.saturating_add(height.saturating_mul(10))),
        nonce: U64::new(nonce),
        ..*parent
    }
}

/// `headers` continued with children of `nonce` until it holds `len` headers.
fn extend_to(mut headers: Vec<BlockHeader>, len: usize, nonce: u64) -> Vec<BlockHeader> {
    while headers.len() < len {
        let next = child(headers.last().unwrap(), nonce);
        headers.push(next);
    }
    headers
}

/// A chain of `len` headers from the genesis block.
fn chain(len: usize, nonce: u64) -> Vec<BlockHeader> {
    extend_to(vec![genesis_with(0)], len, nonce)
}

/// The headers `0..=at` of `base`, continued to `len` headers on a branch of `nonce`.
fn fork(base: &[BlockHeader], at: usize, len: usize, nonce: u64) -> Vec<BlockHeader> {
    extend_to(base.get(..=at).unwrap().to_vec(), len, nonce)
}

/// A target off the schedule, which the proof of work still meets.
fn off_schedule() -> Target {
    let mut bytes = [0xff; 32];
    bytes[31] = 0xfe;
    Target(bytes)
}

fn id_at(headers: &[BlockHeader], height: usize) -> BlockId {
    block_id(headers.get(height).unwrap())
}

type Shared = Arc<Mutex<Vec<BlockHeader>>>;

/// A full node on a free port that serves `chain` as the head and the headers of a range
/// until the test ends. The chain can be replaced through the handle.
fn serve_chain(chain: Vec<BlockHeader>) -> (String, Shared) {
    let shared = Arc::new(Mutex::new(chain));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let served = Arc::clone(&shared);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            answer(stream, &served);
        }
    });
    (url, shared)
}

fn number(query: &str, name: &str) -> Option<u64> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .and_then(|(_, value)| value.parse().ok())
}

fn answer(mut stream: TcpStream, chain: &Shared) {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(buffer.get(..read).unwrap());
    }
    let text = String::from_utf8(request).unwrap();
    let target = text
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .to_owned();
    let (path, query) = target.split_once('?').unwrap_or((target.as_str(), ""));
    let chain = chain.lock().unwrap();
    let body = if path == "/v1/blocks/head" {
        serde_json::to_vec(&HeaderView::from(chain.last().unwrap())).unwrap()
    } else {
        let from = number(query, "from").unwrap_or(0);
        let to = number(query, "to").unwrap_or(u64::MAX);
        let headers = chain
            .iter()
            .filter(|header| (from..=to).contains(&header.height.get()))
            .map(HeaderView::from)
            .collect();
        serde_json::to_vec(&HeadersPage { headers }).unwrap()
    };
    stream
        .write_all(&http("200 OK", "application/json", &body))
        .unwrap();
}

fn store_path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pouw-sync-{}-{name}.bin", std::process::id()));
    drop(fs::remove_file(&path));
    path
}

fn syncer(urls: &[String]) -> HeaderSync {
    HeaderSync::new(params(), genesis_with(0), Upstream::new(urls))
}

/// A store that holds the genesis block.
fn started(name: &str, sync: &HeaderSync) -> RwLock<HeaderStore> {
    let mut store = HeaderStore::open(&store_path(name), 32).unwrap();
    sync.start(&mut store).unwrap();
    RwLock::new(store)
}

fn tip(store: &RwLock<HeaderStore>) -> (u64, BlockId) {
    let (height, id) = store.read().unwrap().tip().unwrap();
    (height.0, id)
}

fn held(store: &RwLock<HeaderStore>, height: u64) -> BlockId {
    block_id(&store.read().unwrap().get(Height(height)).unwrap().unwrap())
}

#[test]
fn an_empty_store_starts_at_genesis_and_catches_up() {
    let full = chain(25, 1);
    let (url, _node) = serve_chain(full.clone());
    let sync = syncer(&[url]);
    let store = started("catch-up", &sync);
    assert_eq!(tip(&store).0, 0);

    assert_eq!(
        sync.step(&store, NOW).unwrap(),
        Outcome::Extended { added: 24 }
    );
    assert_eq!(tip(&store), (24, id_at(&full, 24)));
    assert_eq!(sync.step(&store, NOW).unwrap(), Outcome::Synced);
}

#[test]
fn a_chain_longer_than_one_range_is_read_in_ranges() {
    let full = chain(1002, 1);
    let (url, _node) = serve_chain(full.clone());
    let sync = syncer(&[url]);
    let store = started("ranges", &sync);
    assert_eq!(
        sync.step(&store, NOW).unwrap(),
        Outcome::Extended { added: 1001 }
    );
    assert_eq!(tip(&store), (1001, id_at(&full, 1001)));
}

#[test]
fn the_head_is_followed_as_the_chain_grows() {
    let (url, node) = serve_chain(chain(10, 1));
    let sync = syncer(&[url]);
    let store = started("follow", &sync);
    sync.step(&store, NOW).unwrap();

    let longer = chain(14, 1);
    *node.lock().unwrap() = longer.clone();
    assert_eq!(
        sync.step(&store, NOW).unwrap(),
        Outcome::Extended { added: 4 }
    );
    assert_eq!(tip(&store), (13, id_at(&longer, 13)));
    assert_eq!(sync.step(&store, NOW).unwrap(), Outcome::Synced);
}

#[test]
fn a_node_that_is_behind_changes_nothing() {
    let full = chain(20, 1);
    let (url, node) = serve_chain(full.clone());
    let sync = syncer(&[url]);
    let store = started("behind", &sync);
    sync.step(&store, NOW).unwrap();

    *node.lock().unwrap() = chain(12, 1);
    assert_eq!(sync.step(&store, NOW).unwrap(), Outcome::Synced);
    assert_eq!(tip(&store), (19, id_at(&full, 19)));
}

#[test]
fn a_branch_with_more_work_replaces_the_tip_of_ours() {
    let old = chain(20, 1);
    let (url, node) = serve_chain(old.clone());
    let sync = syncer(&[url]);
    let store = started("reorg", &sync);
    sync.step(&store, NOW).unwrap();
    assert_eq!(tip(&store), (19, id_at(&old, 19)));

    let new = fork(&old, 11, 25, 2);
    *node.lock().unwrap() = new.clone();
    assert_eq!(
        sync.step(&store, NOW).unwrap(),
        Outcome::Reorganized {
            dropped: 8,
            added: 13
        }
    );
    assert_eq!(tip(&store), (24, id_at(&new, 24)));
    assert_eq!(held(&store, 11), id_at(&old, 11));
    assert_eq!(held(&store, 12), id_at(&new, 12));
    assert!(
        store
            .read()
            .unwrap()
            .find(&id_at(&old, 15))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_branch_without_more_work_is_not_followed() {
    let old = chain(20, 1);
    let (url, node) = serve_chain(old.clone());
    let sync = syncer(&[url]);
    let store = started("kept", &sync);
    sync.step(&store, NOW).unwrap();

    *node.lock().unwrap() = fork(&old, 11, 20, 2);
    assert_eq!(sync.step(&store, NOW).unwrap(), Outcome::Kept);
    assert_eq!(tip(&store), (19, id_at(&old, 19)));
    assert_eq!(held(&store, 15), id_at(&old, 15));
}

/// `base` up to `at`, then `len` headers of which the one at index `bad` is off the
/// schedule.
fn branch_with_a_bad_header(
    base: &[BlockHeader],
    at: usize,
    len: usize,
    bad: usize,
) -> Vec<BlockHeader> {
    let mut headers = base.get(..=at).unwrap().to_vec();
    for index in 0..len {
        let mut next = child(headers.last().unwrap(), 2);
        if index == bad {
            next.target = off_schedule();
        }
        headers.push(next);
    }
    headers
}

#[test]
fn a_branch_that_fails_the_checks_leaves_our_chain_as_it_was() {
    let old = chain(20, 1);
    let (url, node) = serve_chain(old.clone());
    let sync = syncer(&[url]);
    let store = started("rollback", &sync);
    sync.step(&store, NOW).unwrap();

    // longer than ours, so it is tried; its fourth header breaks the target rule
    *node.lock().unwrap() = branch_with_a_bad_header(&old, 11, 13, 3);
    let error = sync.step(&store, NOW).unwrap_err();
    assert!(
        matches!(error, SyncError::Verify(VerifyError::Header(_))),
        "{error}"
    );
    assert_eq!(tip(&store), (19, id_at(&old, 19)));
    for height in 0..20 {
        assert_eq!(
            held(&store, height),
            id_at(&old, usize::try_from(height).unwrap())
        );
    }
    assert_eq!(store.read().unwrap().len(), 20);
}

#[test]
fn a_node_on_another_genesis_is_refused() {
    let (url, node) = serve_chain(chain(10, 1));
    let sync = syncer(&[url]);
    let store = started("genesis", &sync);
    sync.step(&store, NOW).unwrap();

    *node.lock().unwrap() = extend_to(vec![genesis_with(1)], 12, 1);
    let error = sync.step(&store, NOW).unwrap_err();
    assert!(matches!(error, SyncError::OtherGenesis), "{error}");
    assert_eq!(tip(&store).0, 9);
}

#[test]
fn a_store_of_another_genesis_is_refused_at_the_start() {
    let sync = syncer(&[]);
    let store = started("start", &sync);
    let other = HeaderSync::new(params(), genesis_with(1), Upstream::new(&[]));
    let error = other.start(&mut store.write().unwrap()).unwrap_err();
    assert!(matches!(error, SyncError::OtherGenesis), "{error}");
}

#[test]
fn the_start_does_not_touch_a_store_that_holds_headers() {
    let full = chain(6, 1);
    let (url, _node) = serve_chain(full.clone());
    let sync = syncer(&[url]);
    let store = started("restart", &sync);
    sync.step(&store, NOW).unwrap();
    sync.start(&mut store.write().unwrap()).unwrap();
    assert_eq!(tip(&store), (5, id_at(&full, 5)));
}

#[test]
fn the_next_full_node_is_used_when_one_cannot_be_reached() {
    let full = chain(15, 1);
    let (url, _node) = serve_chain(full.clone());
    let sync = syncer(&[dead_node(), url]);
    let store = started("fallback", &sync);
    assert_eq!(
        sync.step(&store, NOW).unwrap(),
        Outcome::Extended { added: 14 }
    );
    assert_eq!(tip(&store), (14, id_at(&full, 14)));
}

#[test]
fn a_node_that_sends_a_bad_header_is_left_for_the_next_one() {
    let honest = chain(20, 1);
    // the same chain up to height 2, then a header off the schedule
    let liar = branch_with_a_bad_header(&honest, 2, 17, 0);
    let (liar_url, _liar) = serve_chain(liar);
    let (honest_url, _honest) = serve_chain(honest.clone());
    let sync = syncer(&[liar_url, honest_url]);
    let store = started("liar", &sync);

    // the liar's headers 1 and 2 are the honest ones and stay, the rest comes from the
    // honest node
    assert_eq!(
        sync.step(&store, NOW).unwrap(),
        Outcome::Extended { added: 17 }
    );
    assert_eq!(tip(&store), (19, id_at(&honest, 19)));
}

#[test]
fn with_no_full_node_there_is_nothing_to_follow() {
    let sync = syncer(&[]);
    let store = started("none", &sync);
    let error = sync.step(&store, NOW).unwrap_err();
    assert!(matches!(error, SyncError::NoNodes), "{error}");
}

#[test]
fn the_devnet_spec_gives_its_genesis() {
    let (spec, genesis) = load_chain(None).unwrap();
    assert_eq!(genesis.height.get(), 0);
    assert_eq!(block_id(&genesis), spec.expected_genesis_id);
}

#[test]
fn a_spec_file_that_is_missing_is_an_error() {
    let error = load_chain(Some(Path::new("/nonexistent/chain.json"))).unwrap_err();
    assert!(matches!(error, SpecLoadError::Read { .. }), "{error}");
}
