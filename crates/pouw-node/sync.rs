//! Chain sync over [`SyncRequest`] and [`SyncResponse`]: answering the requests of
//! peers from the store, and asking peers for headers and blocks. A request of the node
//! is sent with a [`RequestId`] and kept in a table of pending requests until the
//! transport answers it with that id. Headers-first initial block download is
//! pouw-node#90, built on these requests in `ibd::on_headers`.
//!
//! ```text
//!  Status of a peer with more work   -> ask_headers   GetHeaders { our locator }
//!  announce, parent not indexed      -> ask_headers
//!  announce, parent indexed          -> chain::receive_header, ask_block id
//!  Headers answer                    -> ibd::on_headers (pouw-node#90)
//!  Blocks answer                     -> chain pipeline, in order
//! ```
//!
//! A locator lists ids of the canonical chain from the tip down: the last
//! [`DENSE_LOCATOR_IDS`] heights one by one, then steps that double, and always the genesis
//! as the last id. The answering node takes the first id it has on its canonical chain
//! as the fork point and sends the headers after it, so two nodes on different forks
//! find their common ancestor in one round trip with at most [`MAX_LOCATOR_IDS`] ids.

use pouw_types::{BlockHeader, BlockId, Height};
use thiserror::Error;
use tracing::debug;

use crate::{
    metrics::Metrics,
    p2p::{
        self, Command, Delivery, GetBlocks, GetHeaders, Misbehavior, Network, NetworkError, PeerIx,
        RequestId, SyncRequest, SyncResponse, TransportGone,
        limits::{MAX_BLOCKS_PER_REQUEST, MAX_HEADERS_PER_RESPONSE, MAX_LOCATOR_IDS},
    },
    precheck::{CheckedBlock, Fetched},
    store::{self, Reader, Store, StoreError},
};

/// Heights at the top of a locator that are listed one by one.
pub const DENSE_LOCATOR_IDS: usize = 10;

/// A request of the node that waits for its answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    pub id: RequestId,
    pub peer: PeerIx,
    pub request: SyncRequest,
}

/// The requests of the node in the order they were sent. Request ids come from a
/// counter that only goes up, so the table is sorted by id, and a lookup scans the few
/// entries in flight.
pub type Pending = Vec<PendingRequest>;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error(transparent)]
    TransportGone(#[from] TransportGone),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("the request ids are exhausted")]
    IdsExhausted,
}

/// The heights a locator of a chain with tip `tip` lists, from the tip down to 0.
///
/// The first [`DENSE_LOCATOR_IDS`] heights are the tip and the heights just below it.
/// From the tenth on the gap between two heights doubles each time (1, 2, 4, ...), a
/// gap past 0 is clamped to 0, and 0 is always last. A tip of 25 gives
/// `25..=16, 15, 13, 9, 1, 0`. The list is cut to
/// [`MAX_LOCATOR_IDS`] heights, the last of them 0, so a tip
/// near `u64::MAX` keeps its newest heights and the genesis.
pub fn locator_heights(tip: Height) -> Vec<Height> {
    let mut heights = Vec::new();
    let mut height = tip.0;
    let mut step = 1u64;
    loop {
        heights.push(Height(height));
        if height == 0 {
            return heights;
        }
        if heights.len() >= MAX_LOCATOR_IDS.saturating_sub(1) {
            heights.push(Height(0));
            return heights;
        }
        height = height.saturating_sub(step);
        if heights.len() >= DENSE_LOCATOR_IDS {
            step = step.saturating_mul(2);
        }
    }
}

/// The locator of the canonical chain of `reader`, newest first. An empty store has an
/// empty locator.
pub fn locator(reader: &Reader<'_>) -> Result<Vec<BlockId>, StoreError> {
    let Some(tip) = store::tip(reader)? else {
        return Ok(Vec::new());
    };
    locator_heights(tip.height)
        .into_iter()
        .map(|height| {
            store::canonical_id(reader, height)?
                .ok_or_else(|| StoreError::Corrupt("a canonical height has no block".into()))
        })
        .collect()
}

/// The height of the first id of `locator` that is on the canonical chain of `reader`:
/// an id whose entry is indexed and whose height holds that same id as canonical. Ids
/// of other forks and unknown ids are skipped. `None` when no id matches, which is a
/// peer on another chain.
pub fn fork_point(reader: &Reader<'_>, locator: &[BlockId]) -> Result<Option<Height>, StoreError> {
    for id in locator {
        let Some(entry) = store::index(reader, id)? else {
            continue;
        };
        let height = Height(entry.height.get());
        if store::canonical_id(reader, height)? == Some(*id) {
            return Ok(Some(height));
        }
    }
    Ok(None)
}

/// The headers after the fork point of `request` on the canonical chain, ascending, at
/// most [`MAX_HEADERS_PER_RESPONSE`]. The list ends after `stop` when `stop` is on the
/// chain above the fork point, and at the tip otherwise. No fork point gives no headers.
pub fn headers_after(
    reader: &Reader<'_>,
    request: &GetHeaders,
) -> Result<Vec<BlockHeader>, StoreError> {
    let Some(fork) = fork_point(reader, &request.locator)? else {
        return Ok(Vec::new());
    };
    let mut headers = Vec::new();
    let mut next = fork;
    while headers.len() < MAX_HEADERS_PER_RESPONSE {
        let Some(height) = next.checked_next() else {
            break;
        };
        next = height;
        let Some(id) = store::canonical_id(reader, height)? else {
            break;
        };
        let header = store::header(reader, &id)?
            .ok_or_else(|| StoreError::Corrupt("a canonical block is not stored".into()))?;
        headers.push(*header);
        if request.stop == Some(id) {
            break;
        }
    }
    Ok(headers)
}

/// The bodies of the blocks `request` names that the node stores, in the order of the
/// request, as the bytes that were stored. An id without a stored body ends the list: a
/// later body is never sent in its place, so the asker can match answers to ids by
/// position. At most [`MAX_BLOCKS_PER_REQUEST`] ids are read.
pub fn blocks_for(reader: &Reader<'_>, request: &GetBlocks) -> Result<Vec<Vec<u8>>, StoreError> {
    let mut blocks = Vec::new();
    for id in request.ids.iter().take(MAX_BLOCKS_PER_REQUEST) {
        let Some(stored) = store::block(reader, id)? else {
            break;
        };
        blocks.push(stored.bytes.to_vec());
    }
    Ok(blocks)
}

/// The answer to `request` from the store.
pub fn answer(store: &Store, request: &SyncRequest) -> Result<SyncResponse, StoreError> {
    let reader = store::read(store)?;
    match request {
        SyncRequest::GetHeaders(get) => Ok(SyncResponse::Headers(headers_after(&reader, get)?)),
        SyncRequest::GetBlocks(get) => Ok(SyncResponse::Blocks(blocks_for(&reader, get)?)),
    }
}

/// Sends `request` to `peer` and records it as pending. A request the full command
/// channel dropped is not recorded, since no answer will come: the result is `None`.
pub fn request(
    network: &Network,
    pending: &mut Pending,
    next_request: &mut RequestId,
    metrics: &mut Metrics,
    peer: PeerIx,
    request: SyncRequest,
) -> Result<Option<RequestId>, SyncError> {
    let id = *next_request;
    let next = id.0.checked_add(1).ok_or(SyncError::IdsExhausted)?;
    let command = Command::Request {
        id,
        peer,
        request: request.clone(),
    };
    if p2p::send(network, command, metrics)? == Delivery::Dropped {
        return Ok(None);
    }
    *next_request = RequestId(next);
    pending.push(PendingRequest { id, peer, request });
    Ok(Some(id))
}

/// Asks `peer` for the headers after the common ancestor of its chain and ours, with
/// our locator and no `stop`. At most one `GetHeaders` to a peer is pending: a second
/// ask while the first waits changes nothing and gives `None`, so a peer that
/// announces many blocks does not make the node send as many requests.
pub fn ask_headers(
    network: &Network,
    pending: &mut Pending,
    next_request: &mut RequestId,
    store: &Store,
    metrics: &mut Metrics,
    peer: PeerIx,
) -> Result<Option<RequestId>, SyncError> {
    ask_headers_from(network, pending, next_request, store, metrics, peer, None)
}

/// Like [`ask_headers`], with the header `after` ahead of our locator when it is given: the
/// peer answers with the headers after it. Initial block download asks this way for
/// the next page of headers, because the headers it stored are not on our canonical
/// chain yet and our locator alone would bring the same page again. The locator keeps
/// within [`MAX_LOCATOR_IDS`] ids: with `after` it drops our tip, which `after` is above.
pub fn ask_headers_from(
    network: &Network,
    pending: &mut Pending,
    next_request: &mut RequestId,
    store: &Store,
    metrics: &mut Metrics,
    peer: PeerIx,
    after: Option<BlockId>,
) -> Result<Option<RequestId>, SyncError> {
    let waiting = pending.iter().any(|waiting| {
        waiting.peer == peer && matches!(waiting.request, SyncRequest::GetHeaders(_))
    });
    if waiting {
        return Ok(None);
    }
    let ours = locator(&store::read(store)?)?;
    let locator = match after {
        None => ours,
        Some(after) => {
            let skip = usize::from(ours.len() >= MAX_LOCATOR_IDS);
            let mut ids = vec![after];
            ids.extend(ours.into_iter().skip(skip));
            ids
        }
    };
    let get = GetHeaders {
        locator,
        stop: None,
    };
    request(
        network,
        pending,
        next_request,
        metrics,
        peer,
        SyncRequest::GetHeaders(Box::new(get)),
    )
}

/// Asks `peer` for the block `id`, whose header is stored.
pub fn ask_block(
    network: &Network,
    pending: &mut Pending,
    next_request: &mut RequestId,
    metrics: &mut Metrics,
    peer: PeerIx,
    id: BlockId,
) -> Result<Option<RequestId>, SyncError> {
    let get = GetBlocks { ids: vec![id] };
    request(
        network,
        pending,
        next_request,
        metrics,
        peer,
        SyncRequest::GetBlocks(get),
    )
}

/// Forgets the pending requests to `peer`.
pub fn on_peer_disconnected(pending: &mut Pending, peer: PeerIx) {
    pending.retain(|waiting| waiting.peer != peer);
}

/// Blocks a peer sent in answer to a request of the node.
#[derive(Debug)]
pub struct SyncedBlocks {
    pub peer: PeerIx,
    pub blocks: Vec<CheckedBlock>,
}

/// What became of an answer to a request of the node.
#[derive(Debug)]
#[must_use]
pub enum SyncOutcome {
    /// Blocks for the chain pipeline.
    Blocks(SyncedBlocks),
    /// Headers for `ibd::on_headers`.
    Headers {
        peer: PeerIx,
        headers: Vec<BlockHeader>,
    },
    /// The peer answered wrongly or not at all in time: report it.
    Misbehaved(PeerIx, Misbehavior),
    /// The request failed for a reason that is not the peer's fault, such as a
    /// dropped connection.
    Unreachable { peer: PeerIx, error: NetworkError },
    /// The transport itself has stopped.
    TransportStopped,
    /// The answer belongs to no pending request.
    Unsolicited,
}

/// Takes the pending request `id` and sorts its answer for the caller: blocks go to the
/// chain pipeline, a wrong or late answer is a [`Misbehavior`] to report.
pub fn on_response(
    pending: &mut Pending,
    id: RequestId,
    result: Result<Fetched, NetworkError>,
) -> SyncOutcome {
    let Some(at) = pending.iter().position(|waiting| waiting.id == id) else {
        debug!(?id, "answer to no pending request");
        return SyncOutcome::Unsolicited;
    };
    let PendingRequest { peer, request, .. } = pending.remove(at);
    match (request, result) {
        (SyncRequest::GetBlocks(_), Ok(Fetched::Blocks(blocks))) => {
            SyncOutcome::Blocks(SyncedBlocks { peer, blocks })
        }
        (SyncRequest::GetHeaders(_), Ok(Fetched::Headers(headers))) => {
            SyncOutcome::Headers { peer, headers }
        }
        (_, Ok(_)) => SyncOutcome::Misbehaved(peer, Misbehavior::Malformed),
        (_, Err(NetworkError::Timeout)) => SyncOutcome::Misbehaved(peer, Misbehavior::Unresponsive),
        (_, Err(NetworkError::BadAnswer(why))) => SyncOutcome::Misbehaved(peer, why),
        (_, Err(NetworkError::Stopped)) => SyncOutcome::TransportStopped,
        (_, Err(error @ (NetworkError::NotConnected(_) | NetworkError::Transport(_)))) => {
            SyncOutcome::Unreachable { peer, error }
        }
    }
}

#[cfg(test)]
mod tests;
