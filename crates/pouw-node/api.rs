//! The calls of the REST API into the node loop. Each request carries a oneshot
//! sender for its answer; the loop answers it with the read functions of this module.
//!
//! Requests reach the loop through the api channel (capacity
//! [`API_CAPACITY`](crate::node::API_CAPACITY)), which the API and metrics threads feed
//! with [`submit`]. The loop reads it last, after control, work, the tick and p2p. A full
//! channel is [`Refused::Busy`], which the HTTP server answers with
//! `pouw_api::error::ErrorClass::Busy` (503, code `busy`) without waiting.

use std::net::SocketAddr;

use pouw_api::{
    event::EventsPage,
    view::{
        AccountView, BlockView, CircuitView, HeaderView, IncludedProof, InclusionProof,
        MAX_BLOCKS_PER_CALL, MAX_HEADERS_PER_CALL, MempoolView, NodeInfo, ProofTxView,
        SignedTxView, TxStatus, TxView,
    },
};
use pouw_consensus::{ChainTip, InvalidTx, StateView};
use pouw_crypto::{Address, hash_to_field};
use pouw_types::{
    Block, BlockId, ChainId, CircuitId, Height, SignedTx, TxId, TxKind, eta_chain, inclusion_proof,
    mask,
};
use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use crate::{
    chain::TxOutcome,
    events::{self, CursorExpired, EventLog},
    mempool::{self, Mempool},
    node::ComponentFault,
    precheck::CheckedTx,
    store::{self, Reader, Store, StoreError, TxLocation},
};

/// An answer of the store: `None` for something it does not hold.
pub type Answer<T> = oneshot::Sender<Result<Option<T>, StoreError>>;

/// The canonical block a request names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKey {
    /// The tip.
    Head,
    /// The canonical block at this height.
    Height(Height),
    /// The block with this id, when it is on the canonical chain.
    Id(BlockId),
}

/// A canonical block as the API serves it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReply {
    /// The borsh bytes as stored.
    Bytes(Vec<u8>),
    /// The JSON view, with the derived fields of the proof txs.
    View(Box<BlockView>),
}

/// A request for one canonical block. [`ApiRequest`] boxes it to stay small.
#[derive(Debug)]
pub struct BlockQuery {
    /// The block asked for.
    pub key: BlockKey,
    /// Whether the answer is the view and not the stored bytes.
    pub json: bool,
    pub reply: Answer<BlockReply>,
}

/// What a range of heights gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ranged<T> {
    /// The items from `from` up to `to` or the tip, ascending; none when `from` is above
    /// the tip.
    Items(Vec<T>),
    /// `from` is above `to`.
    FromAboveTo,
    /// The range holds more than one call may take.
    TooLarge,
}

/// What a transaction lookup gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxReply {
    /// The borsh bytes of the transaction (for a proof request, the request).
    Bytes(Vec<u8>),
    /// The view, which says whether the transaction is pending or included.
    View(Box<TxView>),
}

#[derive(Debug)]
pub enum ApiRequest {
    /// The canonical tip.
    Tip { reply: Answer<ChainTip> },
    /// A stored header.
    Header {
        id: BlockId,
        reply: Answer<HeaderView>,
    },
    /// A stored block.
    Block { id: BlockId, reply: Answer<Vec<u8>> },
    /// An account at the tip.
    Account {
        address: Address,
        reply: Answer<AccountView>,
    },
    /// A transaction for the mempool and the network, with the verdict of
    /// `precheck::check_tx`. The API thread runs the precheck with a `Scratch` of its own
    /// before it sends the request, so the loop verifies no signature.
    SubmitTx {
        checked: Box<Result<CheckedTx, InvalidTx>>,
        reply: oneshot::Sender<TxOutcome>,
    },
    /// Where the canonical chain holds a transaction.
    TxLocation { id: TxId, reply: Answer<TxLocation> },
    /// A page of the event log.
    Events {
        after: u64,
        limit: u32,
        reply: oneshot::Sender<Result<EventsPage, CursorExpired>>,
    },
    /// The mempool summary.
    Mempool { reply: oneshot::Sender<MempoolView> },
    /// The chain id, the height of the tip and the peer count.
    Node {
        reply: oneshot::Sender<Result<NodeInfo, StoreError>>,
    },
    /// One canonical block, as bytes or as the view.
    CanonicalBlock(Box<BlockQuery>),
    /// One canonical header.
    CanonicalHeader {
        key: BlockKey,
        reply: Answer<HeaderView>,
    },
    /// Canonical blocks `from..=to` (`to` cut to the tip), at most
    /// [`MAX_BLOCKS_PER_CALL`].
    Blocks {
        from: Option<u64>,
        to: Option<u64>,
        json: bool,
        reply: oneshot::Sender<Result<Ranged<BlockReply>, StoreError>>,
    },
    /// Canonical headers `from..=to` (`to` cut to the tip), at most
    /// [`MAX_HEADERS_PER_CALL`].
    Headers {
        from: Option<u64>,
        to: Option<u64>,
        reply: oneshot::Sender<Result<Ranged<HeaderView>, StoreError>>,
    },
    /// One transaction of the canonical chain or of the mempool, as bytes or as the view.
    Tx {
        id: TxId,
        json: bool,
        reply: Answer<TxReply>,
    },
    /// The Merkle inclusion proof of a transaction of the canonical chain.
    Inclusion {
        id: TxId,
        reply: Answer<InclusionProof>,
    },
    /// Every registered circuit, with the key blobs when `keys`.
    Circuits {
        keys: bool,
        reply: oneshot::Sender<Result<Vec<CircuitView>, StoreError>>,
    },
    /// One registered circuit, with the key blobs when `keys`.
    Circuit {
        id: CircuitId,
        keys: bool,
        reply: Answer<CircuitView>,
    },
    /// The text of `/metrics`.
    Metrics { reply: oneshot::Sender<String> },
}

/// Why a request did not reach the node loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Refused {
    /// The api channel is full. The caller answers 503 at once.
    #[error("the node is busy")]
    Busy,
    /// The loop dropped its receiver, which means the node is shutting down.
    #[error("the node loop is gone")]
    NodeGone,
}

/// Queues `request` for the loop without waiting. On `Err` the request, and the oneshot
/// sender in it, is dropped.
pub fn submit(api: &mpsc::Sender<ApiRequest>, request: ApiRequest) -> Result<(), Refused> {
    match api.try_send(request) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => Err(Refused::Busy),
        Err(mpsc::error::TrySendError::Closed(_)) => Err(Refused::NodeGone),
    }
}

/// The API server thread: turns HTTP calls on `addr` into answers, see
/// [`crate::http`]. With `fixtures` set it is the mock node of pouw-node#59 and answers
/// the routes of [`pouw_api::path`] from the fixture chain. Without it the routes ask
/// the node loop through `api` and [`submit`] (a full queue answers 503). The thread
/// runs until the process ends.
pub fn serve(
    addr: SocketAddr,
    fixtures: Option<&std::path::Path>,
    api: &mpsc::Sender<ApiRequest>,
) -> Result<(), ComponentFault> {
    crate::http::serve_api(addr, fixtures, api)
}

pub fn tip(store: &Store) -> Result<Option<ChainTip>, StoreError> {
    store::tip(&store::read(store)?)
}

pub fn header(store: &Store, id: &BlockId) -> Result<Option<HeaderView>, StoreError> {
    let reader = store::read(store)?;
    Ok(store::header(&reader, id)?.map(HeaderView::from))
}

/// The borsh bytes of the block as received and stored.
pub fn block(store: &Store, id: &BlockId) -> Result<Option<Vec<u8>>, StoreError> {
    let reader = store::read(store)?;
    Ok(store::block(&reader, id)?.map(|stored| stored.bytes.to_vec()))
}

pub fn account(store: &Store, address: &Address) -> Result<Option<AccountView>, StoreError> {
    let reader = store::read(store)?;
    let account = reader.account(address)?;
    Ok(account.map(|account| AccountView::new(*address, &account)))
}

pub fn tx_location(store: &Store, id: &TxId) -> Result<Option<TxLocation>, StoreError> {
    store::tx_location(&store::read(store)?, id)
}

pub fn events(log: &EventLog, after: u64, limit: u32) -> Result<EventsPage, CursorExpired> {
    let page = events::page(log, after, limit)?;
    Ok(EventsPage {
        events: page.events.into_iter().cloned().collect(),
        next: page.next,
    })
}

/// The tip, the height of a canonical block or a canonical block by id, as an id. A block
/// that is stored but not on the canonical chain is not found.
fn canonical_id_of(reader: &Reader<'_>, key: BlockKey) -> Result<Option<BlockId>, StoreError> {
    Ok(match key {
        BlockKey::Head => store::tip(reader)?.map(|tip| tip.id),
        BlockKey::Height(height) => store::canonical_id(reader, height)?,
        BlockKey::Id(id) => match store::index(reader, &id)? {
            Some(entry) if store::canonical_id(reader, entry.height())? == Some(id) => Some(id),
            _ => None,
        },
    })
}

/// The view of a stored block: its entries and, for each proof tx, the derived `eta`,
/// `mask` and proof system. The registry entry of a circuit does not change once
/// registered, so the tip state gives the proof system of an old block as well.
fn view_of(reader: &Reader<'_>, block: &pouw_types::Block) -> Result<BlockView, StoreError> {
    let etas = eta_chain(
        &block.header.parent,
        &block.compute_txs_root(),
        &block.proof_txs,
    );
    let mut proofs = Vec::with_capacity(block.proof_txs.len());
    for (proof_tx, eta) in block.proof_txs.iter().zip(&etas) {
        let TxKind::ProofRequest { circuit, .. } = &proof_tx.request.body.kind else {
            return Err(StoreError::Corrupt(
                "a stored proof tx does not carry a proof request".to_owned(),
            ));
        };
        let entry = reader.circuit(circuit)?.ok_or_else(|| {
            StoreError::Corrupt(format!(
                "circuit {circuit} of a stored proof tx is not registered"
            ))
        })?;
        let mask = hash_to_field(&mask(&block.header.miner, circuit, proof_tx.usage_counter));
        proofs.push(ProofTxView::new(
            proof_tx,
            hash_to_field(eta),
            mask,
            entry.system,
        ));
    }
    Ok(BlockView::new(block, proofs))
}

fn block_reply(reader: &Reader<'_>, id: &BlockId, json: bool) -> Result<BlockReply, StoreError> {
    let stored = store::block(reader, id)?.ok_or(StoreError::UnknownBlock(*id))?;
    if !json {
        return Ok(BlockReply::Bytes(stored.bytes.to_vec()));
    }
    let block = store::decode(&stored)?;
    Ok(BlockReply::View(Box::new(view_of(reader, &block)?)))
}

/// One canonical block by tip, height or id.
pub fn canonical_block(
    store: &Store,
    key: BlockKey,
    json: bool,
) -> Result<Option<BlockReply>, StoreError> {
    let reader = store::read(store)?;
    let Some(id) = canonical_id_of(&reader, key)? else {
        return Ok(None);
    };
    block_reply(&reader, &id, json).map(Some)
}

/// One canonical header by tip, height or id.
pub fn canonical_header(store: &Store, key: BlockKey) -> Result<Option<HeaderView>, StoreError> {
    let reader = store::read(store)?;
    let Some(id) = canonical_id_of(&reader, key)? else {
        return Ok(None);
    };
    Ok(store::header(&reader, &id)?.map(HeaderView::from))
}

/// The heights `from..=to`, `to` cut to the tip, one item each from the canonical block.
fn ranged<T>(
    store: &Store,
    from: Option<u64>,
    to: Option<u64>,
    cap: u64,
    mut item: impl FnMut(&Reader<'_>, &BlockId) -> Result<T, StoreError>,
) -> Result<Ranged<T>, StoreError> {
    let reader = store::read(store)?;
    let tip = store::tip(&reader)?.ok_or(StoreError::EmptyChain)?.height.0;
    let from = from.unwrap_or(0);
    let to = to.unwrap_or(tip).min(tip);
    if from > tip {
        return Ok(Ranged::Items(Vec::new()));
    }
    if from > to {
        return Ok(Ranged::FromAboveTo);
    }
    if to.saturating_sub(from) >= cap {
        return Ok(Ranged::TooLarge);
    }
    let mut items = Vec::new();
    for height in from..=to {
        let id = store::canonical_id(&reader, Height(height))?
            .ok_or_else(|| StoreError::Corrupt(format!("no canonical block at height {height}")))?;
        items.push(item(&reader, &id)?);
    }
    Ok(Ranged::Items(items))
}

/// Canonical blocks `from..=to`.
pub fn blocks(
    store: &Store,
    from: Option<u64>,
    to: Option<u64>,
    json: bool,
) -> Result<Ranged<BlockReply>, StoreError> {
    ranged(store, from, to, MAX_BLOCKS_PER_CALL, |reader, id| {
        block_reply(reader, id, json)
    })
}

/// Canonical headers `from..=to`.
pub fn headers(
    store: &Store,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<Ranged<HeaderView>, StoreError> {
    ranged(store, from, to, MAX_HEADERS_PER_CALL, |reader, id| {
        store::header(reader, id)?
            .map(HeaderView::from)
            .ok_or(StoreError::UnknownBlock(*id))
    })
}

/// A transaction of the canonical chain with its block and its leaf in the Merkle tree.
struct Located {
    location: TxLocation,
    block: Block,
    index: usize,
}

fn locate(reader: &Reader<'_>, id: &TxId) -> Result<Option<Located>, StoreError> {
    let Some(location) = store::tx_location(reader, id)? else {
        return Ok(None);
    };
    let stored =
        store::block(reader, &location.block)?.ok_or(StoreError::UnknownBlock(location.block))?;
    let block = store::decode(&stored)?;
    let index = usize::try_from(location.index).unwrap_or(usize::MAX);
    if index >= block.leaf_count() {
        return Err(StoreError::Corrupt(format!(
            "tx {id} is indexed at leaf {index} of block {}, which has {} leaves",
            location.block,
            block.leaf_count()
        )));
    }
    Ok(Some(Located {
        location,
        block,
        index,
    }))
}

fn encode(tx: &SignedTx) -> Result<Vec<u8>, StoreError> {
    borsh::to_vec(tx)
        .map_err(|fault| StoreError::Corrupt(format!("a transaction cannot be encoded: {fault}")))
}

/// A transaction the chain does not hold, if the mempool does.
fn pending(pool: &Mempool, id: &TxId, json: bool) -> Result<Option<TxReply>, StoreError> {
    let Some(tx) = mempool::get(pool, id) else {
        return Ok(None);
    };
    if !json {
        return encode(tx).map(|bytes| Some(TxReply::Bytes(bytes)));
    }
    Ok(Some(TxReply::View(Box::new(TxView {
        txid: *id,
        status: TxStatus::Pending,
        tx: SignedTxView::from(tx),
        height: None,
        index: None,
        proof: None,
    }))))
}

/// `GET /v1/txs/{txid}`: a transaction of the canonical chain, else one of the mempool.
/// For a proof request the answer is the request, and the view carries the fields of its
/// proof tx.
pub fn tx(
    store: &Store,
    pool: &Mempool,
    id: &TxId,
    json: bool,
) -> Result<Option<TxReply>, StoreError> {
    let reader = store::read(store)?;
    let Some(Located {
        location,
        block,
        index,
    }) = locate(&reader, id)?
    else {
        return pending(pool, id, json);
    };
    let (request, proof_at) = if let Some(tx) = block.txs.get(index) {
        (tx, None)
    } else {
        let at = index.saturating_sub(block.txs.len());
        let proof_tx = block.proof_txs.get(at).ok_or_else(|| {
            StoreError::Corrupt(format!("block {} has no leaf {index}", location.block))
        })?;
        (&proof_tx.request, Some(at))
    };
    if !json {
        return encode(request).map(|bytes| Some(TxReply::Bytes(bytes)));
    }
    let proof = match proof_at {
        None => None,
        Some(at) => {
            let derived = view_of(&reader, &block)?
                .proof_txs
                .into_iter()
                .nth(at)
                .ok_or_else(|| {
                    StoreError::Corrupt(format!("block {} has no proof tx {at}", location.block))
                })?;
            Some(IncludedProof {
                eta: derived.eta,
                mask: derived.mask,
                proof_system: derived.proof_system,
                usage_counter: derived.usage_counter,
                proof: derived.proof,
                proof_hash: derived.proof_hash,
            })
        }
    };
    Ok(Some(TxReply::View(Box::new(TxView {
        txid: *id,
        status: TxStatus::Included,
        tx: SignedTxView::from(request),
        height: Some(location.height),
        index: Some(location.index),
        proof,
    }))))
}

/// `GET /v1/txs/{txid}/inclusion`: the path of the leaf of a transaction of the canonical
/// chain. A pending transaction has none.
pub fn inclusion(store: &Store, id: &TxId) -> Result<Option<InclusionProof>, StoreError> {
    let reader = store::read(store)?;
    let Some(found) = locate(&reader, id)? else {
        return Ok(None);
    };
    let path = inclusion_proof(&found.block.leaf_ids(), found.index).map_err(|fault| {
        StoreError::Corrupt(format!(
            "no inclusion proof for the stored tx {id}: {fault}"
        ))
    })?;
    Ok(Some(InclusionProof {
        height: found.location.height,
        index: path.index,
        leaf_count: path.leaf_count,
        siblings: path.siblings,
    }))
}

/// `GET /v1/circuits`: the registry at the tip, ascending by height of registration and
/// then by id.
pub fn circuits(store: &Store, keys: bool) -> Result<Vec<CircuitView>, StoreError> {
    let reader = store::read(store)?;
    Ok(store::circuits(&reader)?
        .iter()
        .map(|entry| CircuitView::new(entry, keys))
        .collect())
}

/// `GET /v1/circuits/{id}`.
pub fn circuit(
    store: &Store,
    id: &CircuitId,
    keys: bool,
) -> Result<Option<CircuitView>, StoreError> {
    let reader = store::read(store)?;
    let entry = reader.circuit(id)?;
    Ok(entry.map(|entry| CircuitView::new(entry, keys)))
}

/// `GET /v1/node`: the chain id of the node, its version, the height of the tip and the
/// peers connected.
pub fn node_info(store: &Store, chain_id: ChainId, peers: u64) -> Result<NodeInfo, StoreError> {
    let tip = store::tip(&store::read(store)?)?.ok_or(StoreError::EmptyChain)?;
    Ok(NodeInfo {
        chain_id,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        height: tip.height,
        peers: u32::try_from(peers).unwrap_or(u32::MAX),
    })
}
