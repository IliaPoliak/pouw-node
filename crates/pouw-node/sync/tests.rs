use pouw_consensus::StateDiff;
use pouw_crypto::{Address, Hash32};
use pouw_types::{Block, BlockHeader, BlockId, Height, Target, U32, U64, block_id};
use tokio::sync::mpsc;

use super::*;
use crate::{
    metrics::Metrics,
    p2p::{
        TransportFailure,
        limits::{MAX_HEADERS_PER_RESPONSE, MAX_LOCATOR_IDS},
    },
    store,
};

fn header(height: u64, parent: BlockId, salt: u64) -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(1),
        system_id: U64::new(0),
        height: U64::new(height),
        parent,
        timestamp: U64::new(height),
        miner: Address([9; 32]),
        tx_root: Hash32::ZERO,
        target: Target([0xff; 32]),
        nonce: U64::new(salt),
    }
}

fn put(store: &mut Store, header: &BlockHeader) -> BlockId {
    let id = block_id(header);
    store::put_header(store, &id, header).unwrap();
    let block = Block {
        header: *header,
        txs: vec![],
        proof_txs: vec![],
    };
    store::put_body(store, &id, &borsh::to_vec(&block).unwrap()).unwrap();
    id
}

/// A store whose canonical chain has the heights 0 to `tip`, and the ids by height.
fn chain(tip: u64) -> (Store, Vec<BlockId>) {
    let mut store = store::memory();
    let mut ids: Vec<BlockId> = Vec::new();
    for height in 0..=tip {
        let parent = ids.last().copied().unwrap_or(BlockId::ZERO);
        let id = put(&mut store, &header(height, parent, 0));
        store::connect_block(&mut store, &id, &[], &StateDiff::default()).unwrap();
        ids.push(id);
    }
    (store, ids)
}

/// Stored headers that fork off the chain after `parent_height`, `len` of them, never
/// connected. Their ids differ from the canonical ones through the nonce.
fn fork(store: &mut Store, ids: &[BlockId], parent_height: usize, len: u64) -> Vec<BlockId> {
    let mut parent = ids[parent_height];
    let mut fork = Vec::new();
    for step in 1..=len {
        let height = u64::try_from(parent_height)
            .unwrap()
            .checked_add(step)
            .unwrap();
        parent = put(store, &header(height, parent, 1));
        fork.push(parent);
    }
    fork
}

fn heights(list: &[u64]) -> Vec<Height> {
    list.iter().copied().map(Height).collect()
}

fn get(locator: Vec<BlockId>, stop: Option<BlockId>) -> GetHeaders {
    GetHeaders { locator, stop }
}

fn height_of(header: &BlockHeader) -> u64 {
    header.height.get()
}

#[test]
fn locator_of_height_25_is_dense_then_doubles_and_ends_at_genesis() {
    assert_eq!(
        locator_heights(Height(25)),
        heights(&[25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 13, 9, 1, 0])
    );
}

#[test]
fn locator_of_a_short_chain_is_every_height() {
    assert_eq!(locator_heights(Height(0)), heights(&[0]));
    assert_eq!(locator_heights(Height(3)), heights(&[3, 2, 1, 0]));
    assert_eq!(
        locator_heights(Height(9)),
        heights(&[9, 8, 7, 6, 5, 4, 3, 2, 1, 0])
    );
}

#[test]
fn locator_of_a_long_chain_is_bounded_descending_and_ends_at_genesis() {
    for tip in [1_000, 1 << 20, 1 << 53, (1 << 54) - 1, u64::MAX] {
        let list = locator_heights(Height(tip));
        assert!(list.len() <= MAX_LOCATOR_IDS, "tip {tip}: {}", list.len());
        assert_eq!(list.first(), Some(&Height(tip)));
        assert_eq!(list.last(), Some(&Height(0)));
        assert!(list.windows(2).all(|pair| pair[0] > pair[1]));
    }
}

#[test]
fn locator_lists_the_canonical_ids_of_the_heights() {
    let (store, ids) = chain(25);
    let reader = store::read(&store).unwrap();
    let list = locator(&reader).unwrap();
    let expected: Vec<BlockId> = [25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 13, 9, 1, 0]
        .into_iter()
        .map(|height| ids[height])
        .collect();
    assert_eq!(list, expected);
}

#[test]
fn locator_of_an_empty_store_is_empty() {
    let store = store::memory();
    let reader = store::read(&store).unwrap();
    assert_eq!(locator(&reader).unwrap(), []);
}

#[test]
fn fork_point_is_the_first_id_on_the_canonical_chain() {
    let (mut store, ids) = chain(10);
    let side = fork(&mut store, &ids, 6, 3);
    let reader = store::read(&store).unwrap();
    let locator = [side[2], side[1], side[0], ids[6], ids[5], ids[0]];
    assert_eq!(fork_point(&reader, &locator).unwrap(), Some(Height(6)));
    assert_eq!(fork_point(&reader, &[side[1]]).unwrap(), None);
}

#[test]
fn fork_point_skips_unknown_ids_and_is_none_without_a_match() {
    let (store, ids) = chain(10);
    let reader = store::read(&store).unwrap();
    let unknown = BlockId(Hash32([0xee; 32]));
    assert_eq!(
        fork_point(&reader, &[unknown, ids[4]]).unwrap(),
        Some(Height(4))
    );
    assert_eq!(fork_point(&reader, &[unknown]).unwrap(), None);
    assert_eq!(fork_point(&reader, &[]).unwrap(), None);
}

#[test]
fn headers_follow_the_fork_point_up_to_the_tip() {
    let (store, ids) = chain(10);
    let reader = store::read(&store).unwrap();
    let headers = headers_after(&reader, &get(vec![ids[7], ids[0]], None)).unwrap();
    let found: Vec<u64> = headers.iter().map(height_of).collect();
    assert_eq!(found, [8, 9, 10]);
    assert_eq!(block_id(&headers[0]), ids[8]);
}

#[test]
fn headers_answer_a_peer_on_a_fork_from_the_common_ancestor() {
    let (mut store, ids) = chain(10);
    let side = fork(&mut store, &ids, 6, 5);
    let reader = store::read(&store).unwrap();
    let theirs = vec![side[4], side[3], side[2], side[1], side[0], ids[6], ids[0]];
    let headers = headers_after(&reader, &get(theirs, None)).unwrap();
    let found: Vec<BlockId> = headers.iter().map(block_id).collect();
    assert_eq!(found, ids[7..=10]);
}

#[test]
fn headers_end_at_stop_inclusive() {
    let (store, ids) = chain(10);
    let reader = store::read(&store).unwrap();
    let headers = headers_after(&reader, &get(vec![ids[2]], Some(ids[5]))).unwrap();
    let found: Vec<u64> = headers.iter().map(height_of).collect();
    assert_eq!(found, [3, 4, 5]);
}

#[test]
fn headers_ignore_a_stop_below_the_fork_point() {
    let (store, ids) = chain(10);
    let reader = store::read(&store).unwrap();
    let headers = headers_after(&reader, &get(vec![ids[8]], Some(ids[3]))).unwrap();
    assert_eq!(headers.len(), 2);
}

#[test]
fn headers_are_empty_at_the_tip_and_without_a_fork_point() {
    let (store, ids) = chain(10);
    let reader = store::read(&store).unwrap();
    assert_eq!(
        headers_after(&reader, &get(vec![ids[10]], None)).unwrap(),
        []
    );
    let unknown = BlockId(Hash32([0xee; 32]));
    assert_eq!(
        headers_after(&reader, &get(vec![unknown], None)).unwrap(),
        []
    );
}

#[test]
fn headers_are_capped_per_response() {
    let top = u64::try_from(MAX_HEADERS_PER_RESPONSE).unwrap() + 5;
    let (store, ids) = chain(top);
    let reader = store::read(&store).unwrap();
    let headers = headers_after(&reader, &get(vec![ids[0]], None)).unwrap();
    assert_eq!(headers.len(), MAX_HEADERS_PER_RESPONSE);
    assert_eq!(height_of(&headers[0]), 1);
    assert_eq!(
        block_id(headers.last().unwrap()),
        ids[MAX_HEADERS_PER_RESPONSE]
    );
}

#[test]
fn blocks_are_served_as_stored_in_the_order_asked() {
    let (store, ids) = chain(4);
    let reader = store::read(&store).unwrap();
    let asked = GetBlocks {
        ids: vec![ids[3], ids[1]],
    };
    let blocks = blocks_for(&reader, &asked).unwrap();
    assert_eq!(blocks.len(), 2);
    for (bytes, id) in blocks.iter().zip(&asked.ids) {
        let stored = store::block(&reader, id).unwrap().unwrap();
        assert_eq!(bytes.as_slice(), stored.bytes.as_ref());
    }
}

#[test]
fn an_unknown_block_ends_the_list() {
    let (store, ids) = chain(4);
    let reader = store::read(&store).unwrap();
    let unknown = BlockId(Hash32([0xee; 32]));
    let asked = GetBlocks {
        ids: vec![ids[2], unknown, ids[1]],
    };
    assert_eq!(blocks_for(&reader, &asked).unwrap().len(), 1);
}

#[test]
fn a_block_without_a_body_ends_the_list() {
    let (mut store, ids) = chain(2);
    let bare = header(3, ids[2], 5);
    let bare_id = block_id(&bare);
    store::put_header(&mut store, &bare_id, &bare).unwrap();
    let reader = store::read(&store).unwrap();
    let asked = GetBlocks {
        ids: vec![bare_id, ids[1]],
    };
    assert_eq!(blocks_for(&reader, &asked).unwrap().len(), 0);
}

#[test]
fn answer_dispatches_by_request() {
    let (store, ids) = chain(5);
    let headers = answer(
        &store,
        &SyncRequest::GetHeaders(Box::new(get(vec![ids[3]], None))),
    );
    let SyncResponse::Headers(headers) = headers.unwrap() else {
        panic!("expected headers");
    };
    assert_eq!(headers.len(), 2);
    let blocks = answer(
        &store,
        &SyncRequest::GetBlocks(GetBlocks { ids: vec![ids[1]] }),
    );
    let SyncResponse::Blocks(blocks) = blocks.unwrap() else {
        panic!("expected blocks");
    };
    assert_eq!(blocks.len(), 1);
}

struct Asker {
    network: Network,
    commands: mpsc::Receiver<Command>,
    pending: Pending,
    next: RequestId,
    metrics: Metrics,
}

fn asker(capacity: usize) -> Asker {
    let (network, commands) = mpsc::channel(capacity);
    Asker {
        network,
        commands,
        pending: Vec::new(),
        next: RequestId(0),
        metrics: Metrics::default(),
    }
}

fn ask_headers_of(a: &mut Asker, store: &Store, peer: PeerIx) -> Option<RequestId> {
    ask_headers(
        &a.network,
        &mut a.pending,
        &mut a.next,
        store,
        &mut a.metrics,
        peer,
    )
    .unwrap()
}

#[test]
fn ask_headers_sends_our_locator_and_records_the_request() {
    let (store, ids) = chain(25);
    let mut a = asker(8);
    let id = ask_headers_of(&mut a, &store, PeerIx(3)).unwrap();
    let Ok(Command::Request {
        id: sent,
        peer,
        request: SyncRequest::GetHeaders(get),
    }) = a.commands.try_recv()
    else {
        panic!("expected a GetHeaders request");
    };
    assert_eq!((sent, peer), (id, PeerIx(3)));
    assert_eq!(get.stop, None);
    assert_eq!(get.locator.first(), Some(&ids[25]));
    assert_eq!(get.locator.last(), Some(&ids[0]));
    assert_eq!(
        a.pending.iter().find(|p| p.id == id).unwrap().peer,
        PeerIx(3)
    );
}

#[test]
fn a_second_ask_for_headers_waits_for_the_first() {
    let (store, _) = chain(5);
    let mut a = asker(8);
    assert!(ask_headers_of(&mut a, &store, PeerIx(3)).is_some());
    assert!(ask_headers_of(&mut a, &store, PeerIx(3)).is_none());
    assert!(ask_headers_of(&mut a, &store, PeerIx(4)).is_some());
    assert_eq!(a.pending.len(), 2);
}

#[test]
fn a_dropped_request_is_not_pending_and_keeps_its_id() {
    let (store, _) = chain(5);
    let mut a = asker(1);
    assert!(ask_headers_of(&mut a, &store, PeerIx(1)).is_some());
    assert!(ask_headers_of(&mut a, &store, PeerIx(2)).is_none());
    assert_eq!(a.pending.len(), 1);
    assert_eq!(a.next, RequestId(1));
    assert_eq!(a.metrics.dropped_commands, 1);
}

#[test]
fn a_request_with_the_last_id_is_refused() {
    let mut a = asker(8);
    a.next = RequestId(u64::MAX);
    let id = BlockId(Hash32([1; 32]));
    let result = ask_block(
        &a.network,
        &mut a.pending,
        &mut a.next,
        &mut a.metrics,
        PeerIx(1),
        id,
    );
    assert!(matches!(result, Err(SyncError::IdsExhausted)));
    assert_eq!(a.pending, Vec::new());
}

#[test]
fn ask_block_names_one_id() {
    let mut a = asker(8);
    let id = BlockId(Hash32([1; 32]));
    ask_block(
        &a.network,
        &mut a.pending,
        &mut a.next,
        &mut a.metrics,
        PeerIx(1),
        id,
    )
    .unwrap()
    .unwrap();
    let Ok(Command::Request {
        request: SyncRequest::GetBlocks(get),
        ..
    }) = a.commands.try_recv()
    else {
        panic!("expected a GetBlocks request");
    };
    assert_eq!(get.ids, [id]);
}

#[test]
fn a_disconnected_peer_loses_its_pending_requests() {
    let (store, _) = chain(5);
    let mut a = asker(8);
    ask_headers_of(&mut a, &store, PeerIx(1));
    ask_headers_of(&mut a, &store, PeerIx(2));
    on_peer_disconnected(&mut a.pending, PeerIx(1));
    assert_eq!(a.pending.len(), 1);
    assert_eq!(a.pending[0].peer, PeerIx(2));
}

fn pending_request(request: SyncRequest) -> (Pending, RequestId) {
    let id = RequestId(5);
    let pending = vec![PendingRequest {
        id,
        peer: PeerIx(9),
        request,
    }];
    (pending, id)
}

fn want_headers() -> SyncRequest {
    SyncRequest::GetHeaders(Box::new(get(vec![], None)))
}

fn want_blocks() -> SyncRequest {
    SyncRequest::GetBlocks(GetBlocks { ids: vec![] })
}

#[test]
fn headers_and_blocks_answers_reach_their_handlers() {
    let (mut pending, id) = pending_request(want_headers());
    let outcome = on_response(&mut pending, id, Ok(Fetched::Headers(vec![])));
    assert!(matches!(
        outcome,
        SyncOutcome::Headers {
            peer: PeerIx(9),
            ..
        }
    ));
    assert_eq!(pending, Vec::new());
    let (mut pending, id) = pending_request(want_blocks());
    let outcome = on_response(&mut pending, id, Ok(Fetched::Blocks(vec![])));
    assert!(matches!(outcome, SyncOutcome::Blocks(_)));
}

#[test]
fn an_answer_of_the_wrong_kind_is_malformed() {
    let (mut pending, id) = pending_request(want_blocks());
    let outcome = on_response(&mut pending, id, Ok(Fetched::Headers(vec![])));
    assert!(matches!(
        outcome,
        SyncOutcome::Misbehaved(PeerIx(9), Misbehavior::Malformed)
    ));
}

#[test]
fn a_late_or_refused_answer_is_a_misbehavior() {
    let (mut pending, id) = pending_request(want_headers());
    let outcome = on_response(&mut pending, id, Err(NetworkError::Timeout));
    assert!(matches!(
        outcome,
        SyncOutcome::Misbehaved(_, Misbehavior::Unresponsive)
    ));
    let (mut pending, id) = pending_request(want_headers());
    let refused = Err(NetworkError::BadAnswer(Misbehavior::InvalidBlock));
    let outcome = on_response(&mut pending, id, refused);
    assert!(matches!(
        outcome,
        SyncOutcome::Misbehaved(_, Misbehavior::InvalidBlock)
    ));
}

#[test]
fn a_transport_failure_is_not_the_fault_of_the_peer() {
    let (mut pending, id) = pending_request(want_headers());
    let failure = Err(NetworkError::Transport(TransportFailure::ConnectionClosed));
    assert!(matches!(
        on_response(&mut pending, id, failure),
        SyncOutcome::Unreachable { .. }
    ));
    let (mut pending, id) = pending_request(want_headers());
    assert!(matches!(
        on_response(&mut pending, id, Err(NetworkError::Stopped)),
        SyncOutcome::TransportStopped
    ));
}

#[test]
fn an_answer_to_no_request_is_unsolicited() {
    let mut pending = Pending::new();
    let outcome = on_response(&mut pending, RequestId(1), Ok(Fetched::Headers(vec![])));
    assert!(matches!(outcome, SyncOutcome::Unsolicited));
}
