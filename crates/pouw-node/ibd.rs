//! Headers-first initial block download (pouw-node#90).
//!
//! A peer that has more work than the node is asked for headers by `node::on_status`,
//! and by `node::on_announce` when an announced parent is unknown. This module takes the
//! answer, [`on_headers`], and turns it into downloads of bodies:
//!
//! ```text
//!  GetHeaders ---------> Headers (at most 2000)
//!                         |  each header: parent is the one before, chain::receive_header
//!                         |  a full answer: GetHeaders again, from the last header
//!                         v
//!                   work of the last header >= min_chain_work and above our tip?
//!                         |  no: keep the headers, fetch nothing
//!                         v  yes
//!                   backlog of the peer: the ids without a body, in height order
//!                         |  one window of at most 16 ids in flight, never two
//!                         v
//!  GetBlocks ----------> Blocks --> node::connect_synced --> verify queue --> chain
//!                         |  the window is answered and the queue is empty: next window
//! ```
//!
//! What it keeps, in [`Ibd`]:
//!
//! - a `Source` per peer that has sent headers: its backlog of ids to fetch, and
//!   whether fetching has started for it (its headers reached the work threshold). A
//!   peer that breaks a rule (`node::report`) or is no longer reachable loses its
//!   source.
//! - one [`Window`], the `GetBlocks` in flight. Only one window is in flight at a time,
//!   for all peers, so a block is never asked of two peers and the bodies reach the verify
//!   queue in height order, which is the order they connect in. A window is asked when the
//!   last one is answered and the verify queue is empty (the queue holds exactly one
//!   window, `miner::VERIFY_QUEUE_CAP`), so the node never has more bodies in memory than
//!   that queue and one answer.
//! - the ids whose verify-work stage is skipped, from `NodeState::assume_valid`.
//!
//! A request that is not answered in time is reported by `sync::on_response` as
//! [`Misbehavior::Unresponsive`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use pouw_types::{BlockHeader, BlockId, CumWork, block_id};
use tracing::debug;

use crate::{
    chain::{self, HeaderOutcome},
    miner::VERIFY_QUEUE_CAP,
    node::{self, NodeFault, NodeState},
    p2p::{
        GetBlocks, Misbehavior, PeerIx, RequestId, SyncRequest,
        limits::{MAX_BLOCKS_PER_REQUEST, MAX_HEADERS_PER_RESPONSE},
    },
    store::{self, Store, StoreError, schema::Status},
    sync::{self, SyncedBlocks},
};

/// What the node keeps of the initial block download.
#[derive(Debug, Default)]
pub struct Ibd {
    sources: BTreeMap<PeerIx, Source>,
    window: Option<Window>,
    assumed: BTreeSet<BlockId>,
}

/// The headers a peer sent that the node may fetch the bodies of.
#[derive(Debug, Default)]
struct Source {
    /// The work of the peer's headers reached the threshold: its backlog is fetched.
    fetching: bool,
    /// Ids whose body is not stored yet, ascending in height, each the child of the one
    /// before (the first is the child of a block with a body).
    backlog: VecDeque<BlockId>,
}

/// The `GetBlocks` in flight.
#[derive(Debug)]
pub struct Window {
    peer: PeerIx,
    request: RequestId,
    ids: Vec<BlockId>,
}

/// The headers of an answer that passed, and why the rest did not.
#[derive(Debug, Default)]
struct Stored {
    /// Ids of the headers that have no body yet, in the order of the answer.
    missing: Vec<BlockId>,
    /// The last header that passed and the work of the chain up to it.
    last: Option<(BlockId, CumWork)>,
    /// The peer broke a rule after the headers above.
    fault: Option<Misbehavior>,
}

/// Takes the headers `peer` sent after a `GetHeaders`, at most
/// `MAX_HEADERS_PER_RESPONSE` of them, each already prechecked for the chain id and
/// its work claim.
///
/// 1. Each header after the first has the id of the one before as parent. A break is
///    [`Misbehavior::InvalidBlock`].
/// 2. Each header goes to `chain::receive_header`: a known header is skipped (but fetched
///    when its body is missing), a stored one is kept, an invalid one or a failed one is
///    [`Misbehavior::InvalidBlock`] and ends the answer, and a header whose parent is not
///    stored, which means the peer ignored our locator, is [`Misbehavior::InvalidBlock`]
///    too.
/// 3. A full answer means more headers follow: `GetHeaders` again with the last header
///    ahead of our own locator.
/// 4. Bodies are fetched only once the work of the last header is at least
///    `NodeState::min_chain_work` and above the work of our tip, so a long chain of little
///    work costs no download.
pub fn on_headers(
    state: &mut NodeState,
    peer: PeerIx,
    headers: &[BlockHeader],
) -> Result<(), NodeFault> {
    let stored = store_headers(state, headers)?;
    if let Some(why) = stored.fault {
        debug!(?peer, ?why, "a peer sent headers that break a rule");
        node::report(state, peer, why)?;
    } else if let Some((tail, work)) = stored.last {
        follow(state, peer, stored.missing, tail, work)?;
        if headers.len() >= MAX_HEADERS_PER_RESPONSE {
            sync::ask_headers_from(
                &state.network,
                &mut state.pending,
                &mut state.next_request,
                &state.store,
                &mut state.metrics,
                peer,
                Some(tail),
            )?;
        }
    }
    advance(state)
}

fn store_headers(state: &mut NodeState, headers: &[BlockHeader]) -> Result<Stored, NodeFault> {
    let now = (state.clock)();
    let mut stored = Stored::default();
    let mut parent: Option<BlockId> = None;
    for header in headers {
        let id = block_id(header);
        if parent.is_some_and(|parent| header.parent != parent) {
            stored.fault = Some(Misbehavior::InvalidBlock);
            break;
        }
        let entry = match chain::receive_header(&mut state.store, &state.params, now, &id, header)?
        {
            HeaderOutcome::Stored(entry) => {
                stored.missing.push(id);
                entry
            }
            HeaderOutcome::Known => {
                let entry = store::index(&store::read(&state.store)?, &id)?
                    .ok_or(StoreError::UnknownBlock(id))?;
                if entry.status.contains(Status::FAILED) {
                    stored.fault = Some(Misbehavior::InvalidBlock);
                    break;
                }
                if !entry.status.contains(Status::BODY_STORED) {
                    stored.missing.push(id);
                }
                entry
            }
            HeaderOutcome::Invalid(_) | HeaderOutcome::UnknownParent => {
                stored.fault = Some(Misbehavior::InvalidBlock);
                break;
            }
        };
        stored.last = Some((id, entry.work()));
        parent = Some(id);
    }
    Ok(stored)
}

/// Adds the headers of an answer to the backlog of `peer`. `missing` is what the answer
/// added, `tail` its last header and `work` the work of the chain up to it.
fn follow(
    state: &mut NodeState,
    peer: PeerIx,
    missing: Vec<BlockId>,
    tail: BlockId,
    work: CumWork,
) -> Result<(), NodeFault> {
    let ours =
        store::tip(&store::read(&state.store)?)?.map_or(CumWork::ZERO, |tip| tip.cumulative_work);
    let fetching = state
        .ibd
        .sources
        .get(&peer)
        .is_some_and(|source| source.fetching);
    let added = if fetching {
        missing
    } else if work >= state.min_chain_work && work > ours {
        // the headers of the earlier answers were kept without a download: the chain
        // behind the last header is the backlog
        walk_back(&state.store, tail)?
    } else {
        Vec::new()
    };
    let source = state.ibd.sources.entry(peer).or_default();
    source.fetching = fetching || !added.is_empty();
    if let Some(assumed) = state.assume_valid
        && let Some(at) = added.iter().position(|id| *id == assumed)
    {
        state.ibd.assumed.extend(source.backlog.iter().copied());
        state
            .ibd
            .assumed
            .extend(added.iter().take(at.saturating_add(1)).copied());
    }
    source.backlog.extend(added);
    Ok(())
}

/// The ids from `tail` down to, not including, the first block with a stored body, in
/// ascending order.
fn walk_back(store: &Store, tail: BlockId) -> Result<Vec<BlockId>, StoreError> {
    let reader = store::read(store)?;
    let mut ids = Vec::new();
    let mut current = tail;
    loop {
        let entry = store::index(&reader, &current)?.ok_or(StoreError::UnknownBlock(current))?;
        if entry.status.contains(Status::BODY_STORED) {
            break;
        }
        ids.push(current);
        let header = store::header(&reader, &current)?.ok_or(StoreError::UnknownBlock(current))?;
        current = header.parent;
    }
    ids.reverse();
    Ok(ids)
}

/// Asks for the next window of bodies when none is in flight and the verify queue has
/// room for it. It is called after every event that can make room: an answer, a verified
/// block, a tick and a peer that left, so a missed call is made up at the next tick.
pub fn advance(state: &mut NodeState) -> Result<(), NodeFault> {
    if state.ibd.window.is_some() || !state.work.verify_queue.is_empty() {
        return Ok(());
    }
    let peers: Vec<PeerIx> = state
        .ibd
        .sources
        .iter()
        .filter(|(_, source)| source.fetching)
        .map(|(peer, _)| *peer)
        .collect();
    for peer in peers {
        let ids = next_ids(state, peer)?;
        if ids.is_empty() {
            continue;
        }
        let request = SyncRequest::GetBlocks(GetBlocks { ids: ids.clone() });
        let sent = sync::request(
            &state.network,
            &mut state.pending,
            &mut state.next_request,
            &mut state.metrics,
            peer,
            request,
        )?;
        match sent {
            Some(request) => state.ibd.window = Some(Window { peer, request, ids }),
            None => put_back(&mut state.ibd, peer, ids),
        }
        return Ok(());
    }
    Ok(())
}

/// Takes the next ids of the backlog of `peer`, up to a window, leaving out the ones whose
/// body arrived another way (an announce, say).
fn next_ids(state: &mut NodeState, peer: PeerIx) -> Result<Vec<BlockId>, NodeFault> {
    let Some(source) = state.ibd.sources.get_mut(&peer) else {
        return Ok(Vec::new());
    };
    let reader = store::read(&state.store)?;
    let mut ids = Vec::new();
    while ids.len() < MAX_BLOCKS_PER_REQUEST {
        let Some(id) = source.backlog.pop_front() else {
            break;
        };
        let held = store::index(&reader, &id)?
            .is_some_and(|entry| entry.status.contains(Status::BODY_STORED));
        if !held {
            ids.push(id);
        }
    }
    Ok(ids)
}

/// Returns `ids` to the front of the backlog of `peer`.
fn put_back(ibd: &mut Ibd, peer: PeerIx, ids: Vec<BlockId>) {
    if let Some(source) = ibd.sources.get_mut(&peer) {
        for id in ids.into_iter().rev() {
            source.backlog.push_front(id);
        }
    }
}

/// Takes the window when `request` is its request, so the answer is the one of the
/// window and not of an announce.
pub fn take_window(ibd: &mut Ibd, request: RequestId) -> Option<Window> {
    ibd.window.take_if(|window| window.request == request)
}

/// Takes the bodies a peer sent for `window`: they must be the ids of the window in
/// order, and fewer is allowed (the peer does not have the rest: it is no source any
/// more, without a penalty). More, or other blocks, are [`Misbehavior::Malformed`]. Bodies
/// that do not fit in the verify queue are dropped and their ids go back to the backlog.
pub fn on_window(
    state: &mut NodeState,
    window: Window,
    synced: SyncedBlocks,
) -> Result<(), NodeFault> {
    let SyncedBlocks { peer, blocks } = synced;
    let in_order = blocks.len() <= window.ids.len()
        && blocks
            .iter()
            .zip(&window.ids)
            .all(|(block, id)| block_id(&block.block.header) == *id);
    if !in_order {
        return node::report(state, peer, Misbehavior::Malformed);
    }
    let room = VERIFY_QUEUE_CAP.saturating_sub(state.work.verify_queue.len());
    if blocks.len() > room {
        put_back(&mut state.ibd, peer, window.ids);
        return Ok(());
    }
    let short = blocks.len() < window.ids.len();
    node::connect_synced(state, SyncedBlocks { peer, blocks })?;
    if short {
        forget_source(&mut state.ibd, peer);
    }
    Ok(())
}

/// Whether the verify-work stage of `id` is skipped, and forgets the id: it is an
/// ancestor of `NodeState::assume_valid` that the node is downloading.
pub fn take_assumed(ibd: &mut Ibd, id: &BlockId) -> bool {
    ibd.assumed.remove(id)
}

/// The peer is no source of bodies any more, and its blocks still in the verify queue are
/// dropped: they extend a block that was not accepted, or come from a peer that is not
/// trusted any more.
pub fn forget_peer(state: &mut NodeState, peer: PeerIx) {
    forget_source(&mut state.ibd, peer);
    state.work.verify_queue.retain(|queued| queued.peer != peer);
}

/// The peer is no source of bodies any more.
pub fn forget_source(ibd: &mut Ibd, peer: PeerIx) {
    drop(ibd.sources.remove(&peer));
}

/// A peer disconnected: its source and its window are gone, and the next source goes on.
pub fn on_peer_disconnected(state: &mut NodeState, peer: PeerIx) -> Result<(), NodeFault> {
    forget_source(&mut state.ibd, peer);
    state.ibd.window.take_if(|window| window.peer == peer);
    advance(state)
}
