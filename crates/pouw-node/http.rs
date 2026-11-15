//! The HTTP servers of the node: the API on the API address (`node-api.md`, plus
//! `/health`) and `/metrics` on the metrics address.
//!
//! The API has two modes:
//!
//! - **Fixtures** (`POUW_API_FIXTURES=<folder>` holds `chain.json`, see
//!   `contracts/fixtures` in pouw-docs): the read endpoints, the event log and
//!   `POST /v1/txs` are answered from the fixture chain. This is the mock node for the
//!   indexer, the workload generator and the web API (pouw-node#59). Accounts are
//!   mocked: every address that appears in the chain has [`MOCK_BALANCE`] and the nonce
//!   it has in the chain. A submitted transaction is checked and kept in memory as
//!   pending, never included in a block, so `GET /v1/txs/{txid}` answers `pending` and
//!   `GET /v1/mempool` lists it.
//!
//!   The GETs of a block, a header and a tx answer borsh, the default of
//!   `node-api.md`, and the JSON view when `Accept` names `application/json`. A list of
//!   blocks is JSON unless `Accept` names `application/octet-stream`, then the borsh
//!   blocks follow one another, each prefixed by its u32 length.
//! - **Node**: every route asks the node loop through the api channel and answers from
//!   the store, the mempool and the event log: node, head, block, header, blocks,
//!   headers, account, transaction, inclusion proof, circuits, circuit, mempool, events
//!   and `POST /v1/txs`. A transaction is served from the canonical chain, else from the
//!   mempool as `pending`; its inclusion proof only once it is in a block. `GET /v1/events`
//!   holds a request up to `wait_ms` (at most 30 s) while nothing is new.
//!
//! `/metrics` always asks the node loop, whatever the mode.

#![allow(
    clippy::needless_pass_by_value,
    clippy::unused_async,
    clippy::result_large_err
)]

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use pouw_api::{
    error::{ErrorBody, ErrorClass, ErrorDetail, ErrorDetails, code},
    event::{BlockAccepted, Event, EventKind, EventTime, EventsPage, NodeId},
    path,
    view::{
        AccountView, BlockView, BlocksPage, CircuitView, HeaderView, HeadersPage, IncludedProof,
        InclusionProof, MAX_BLOCKS_PER_CALL, MAX_HEADERS_PER_CALL, MempoolView, NodeInfo,
        ProofTxView, SignedTxView, SubmitTxResponse, TxStatus, TxView,
    },
};
use pouw_consensus::Scratch;
use pouw_crypto::Address;
use pouw_types::{
    Amount, Block, BlockHeader, BlockId, ChainId, CircuitEntry, CircuitId, Height, Nonce, ProofTx,
    SignedTx, TxId, TxKind, inclusion_proof, txid, verify_tx,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::{
    api::{ApiRequest, BlockKey, BlockQuery, BlockReply, Ranged, Refused, TxReply, submit},
    chain::TxOutcome,
    events::CursorExpired,
    mempool::MempoolError,
    node::ComponentFault,
    precheck::check_tx,
    store::StoreError,
};

/// The balance every address of the fixture chain has in fixtures mode.
pub const MOCK_BALANCE: u64 = 1_000_000;

/// How long `/metrics` waits for the node loop.
const METRICS_WAIT: Duration = Duration::from_secs(5);

/// How long a route waits for the node loop.
const ASK_WAIT: Duration = Duration::from_secs(5);

/// The longest `wait_ms` of `GET /v1/events` holds a request (`node-events.md`).
const MAX_EVENTS_WAIT: Duration = Duration::from_secs(30);

/// How often a held `GET /v1/events` asks the node loop for news.
const EVENTS_POLL: Duration = Duration::from_millis(200);

/// Most transactions the mock keeps as pending, a submission over it answers 503.
const MAX_PENDING: usize = 4096;

/// The transactions submitted to the mock, by txid.
type PendingTxs = Arc<Mutex<BTreeMap<TxId, SignedTx>>>;

/// The chain of `chain.json`.
#[derive(Debug)]
struct Chain {
    chain_id: ChainId,
    blocks: Vec<BlockView>,
}

#[derive(Deserialize)]
struct ChainFile {
    chain_id: ChainId,
    blocks: Vec<BlockView>,
}

impl Chain {
    fn load(dir: &Path) -> Result<Self, String> {
        let file = dir.join("chain.json");
        let text =
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        let parsed: ChainFile =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", file.display()))?;
        if parsed.blocks.is_empty() {
            return Err(format!("{}: no blocks", file.display()));
        }
        for (index, block) in parsed.blocks.iter().enumerate() {
            let expected = u64::try_from(index).map_err(|e| e.to_string())?;
            if block.header.height.get() != expected {
                return Err(format!(
                    "{}: block {index} has height {}",
                    file.display(),
                    block.header.height.get()
                ));
            }
        }
        Ok(Self {
            chain_id: parsed.chain_id,
            blocks: parsed.blocks,
        })
    }

    fn tip(&self) -> &BlockView {
        // `load` rejects an empty chain.
        &self.blocks[self.blocks.len().saturating_sub(1)]
    }

    fn tip_height(&self) -> u64 {
        self.tip().header.height.get()
    }

    /// A block by decimal height or `blk:` id.
    fn block(&self, key: &str) -> Option<&BlockView> {
        if let Ok(height) = key.parse::<u64>() {
            return self.blocks.get(usize::try_from(height).ok()?);
        }
        let id: BlockId = parse(key)?;
        self.blocks.iter().find(|block| block.id == id)
    }

    /// The blocks `from..=to`, `to` cut to the tip, at most `cap` of them.
    #[allow(clippy::result_large_err)]
    fn window(&self, range: &Range, cap: u64) -> Result<&[BlockView], Response> {
        let tip = self.tip_height();
        let from = range.from.unwrap_or(0);
        let to = range.to.unwrap_or(tip).min(tip);
        if from > tip {
            return Ok(&[]);
        }
        if from > to {
            return Err(error(
                ErrorClass::Malformed,
                code::MALFORMED,
                "from is above to",
            ));
        }
        if to.saturating_sub(from) >= cap {
            return Err(error(
                ErrorClass::Rejected,
                code::RANGE_TOO_LARGE,
                "the range is over the cap of one call",
            ));
        }
        let (Ok(from), Ok(to)) = (usize::try_from(from), usize::try_from(to)) else {
            return Ok(&[]);
        };
        Ok(self.blocks.get(from..=to).unwrap_or(&[]))
    }

    /// The transaction `id` (a txid, or the txid of a request that has a proof tx).
    fn find(&self, id: &TxId) -> Option<Found<'_>> {
        for block in &self.blocks {
            for (index, tx) in block.txs.iter().enumerate() {
                if tx.txid == *id {
                    return Some(Found {
                        block,
                        index,
                        tx,
                        proof: None,
                    });
                }
            }
            for (offset, proof) in block.proof_txs.iter().enumerate() {
                if proof.request_txid == *id {
                    return Some(Found {
                        block,
                        index: block.txs.len().saturating_add(offset),
                        tx: &proof.request,
                        proof: Some(proof),
                    });
                }
            }
        }
        None
    }

    /// Every transaction of the chain: `txs` and the requests of the proof txs.
    fn all_txs(&self) -> impl Iterator<Item = (&BlockView, &SignedTxView)> {
        self.blocks.iter().flat_map(|block| {
            block
                .txs
                .iter()
                .chain(block.proof_txs.iter().map(|proof| &proof.request))
                .map(move |tx| (block, tx))
        })
    }
}

struct Found<'a> {
    block: &'a BlockView,
    index: usize,
    tx: &'a SignedTxView,
    proof: Option<&'a ProofTxView>,
}

#[derive(Clone)]
struct App {
    chain: Option<Arc<Chain>>,
    api: mpsc::Sender<ApiRequest>,
    pending: PendingTxs,
}

#[derive(Deserialize)]
struct Range {
    from: Option<u64>,
    to: Option<u64>,
}

#[derive(Deserialize)]
struct EventsQuery {
    after: Option<u64>,
    limit: Option<u32>,
    wait_ms: Option<u64>,
}

#[derive(Deserialize)]
struct Include {
    include: Option<String>,
}

/// An id or address of the URL: the JSON string form is the text form.
fn parse<T: DeserializeOwned>(text: &str) -> Option<T> {
    serde_json::from_value(Value::String(text.to_owned())).ok()
}

fn error(class: ErrorClass, code: &str, message: &str) -> Response {
    let status = StatusCode::from_u16(class.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(ErrorBody::new(code, message))).into_response()
}

fn not_found(what: &str) -> Response {
    error(ErrorClass::NotFound, code::NOT_FOUND, what)
}

fn malformed(what: &str) -> Response {
    error(ErrorClass::Malformed, code::MALFORMED, what)
}

fn refusal(refused: Refused) -> Response {
    error(ErrorClass::Busy, code::BUSY, &refused.to_string())
}

fn internal(what: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorBody::new("internal", what)),
    )
        .into_response()
}

/// Whether `Accept` names `media`, parameters such as `q=` ignored.
fn accepts(headers: &HeaderMap, media: &str) -> bool {
    headers
        .get_all(header::ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|item| item.split(';').next())
        .any(|item| item.trim().eq_ignore_ascii_case(media))
}

/// A block, header or tx GET: borsh unless the client asks for the JSON view, the
/// default of `node-api.md`.
fn wants_json(headers: &HeaderMap) -> bool {
    accepts(headers, "application/json")
}

fn octets(bytes: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/octet-stream")], bytes).into_response()
}

/// The borsh answer for `value`.
fn borsh_of<T: borsh::BorshSerialize>(value: &T) -> Response {
    match borsh::to_vec(value) {
        Ok(bytes) => octets(bytes),
        Err(e) => internal(&e.to_string()),
    }
}

/// The block `view` shows, rebuilt from the signed parts the view carries.
fn block_of(view: &BlockView) -> Block {
    Block {
        header: view.header,
        txs: view.txs.iter().map(|tx| tx.tx.clone()).collect(),
        proof_txs: view
            .proof_txs
            .iter()
            .map(|proof| ProofTx {
                request: proof.request.tx.clone(),
                usage_counter: proof.usage_counter,
                proof: proof.proof.clone(),
            })
            .collect(),
    }
}

/// The borsh blocks of `window` one after another, each prefixed by its length as a
/// little-endian u32.
fn length_prefixed(window: &[BlockView]) -> Response {
    let mut out = Vec::new();
    for view in window {
        let Ok(bytes) = borsh::to_vec(&block_of(view)) else {
            return internal("cannot encode a block");
        };
        let Ok(len) = u32::try_from(bytes.len()) else {
            return internal("a block is over the u32 length prefix");
        };
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&bytes);
    }
    octets(out)
}

fn header_answer(headers: &HeaderMap, value: &BlockHeader) -> Response {
    if wants_json(headers) {
        Json(HeaderView::from(value)).into_response()
    } else {
        borsh_of(value)
    }
}

// ---------------------------------------------------------------- handlers

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn metrics(State(app): State<App>) -> Response {
    let (reply, answer) = oneshot::channel();
    if let Err(refused) = submit(&app.api, ApiRequest::Metrics { reply }) {
        return refusal(refused);
    }
    match tokio::time::timeout(METRICS_WAIT, answer).await {
        Ok(Ok(text)) => (
            [(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            text,
        )
            .into_response(),
        _ => error(
            ErrorClass::Busy,
            code::BUSY,
            "the node did not answer in time",
        ),
    }
}

async fn node_info(State(app): State<App>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_node(&app).await;
    };
    Json(NodeInfo {
        chain_id: chain.chain_id,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        height: Height(chain.tip_height()),
        peers: 0,
    })
    .into_response()
}

async fn head(State(app): State<App>, headers: HeaderMap) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_header(&app, &headers, Some(BlockKey::Head)).await;
    };
    header_answer(&headers, &chain.tip().header)
}

async fn block(
    State(app): State<App>,
    UrlPath(key): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_block(&app, &headers, block_key(&key)).await;
    };
    match chain.block(&key) {
        Some(block) if wants_json(&headers) => Json(block).into_response(),
        Some(block) => borsh_of(&block_of(block)),
        None => not_found("no such block"),
    }
}

async fn block_header(
    State(app): State<App>,
    UrlPath(key): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_header(&app, &headers, block_key(&key)).await;
    };
    match chain.block(&key) {
        Some(block) => header_answer(&headers, &block.header),
        None => not_found("no such block"),
    }
}

async fn blocks(
    State(app): State<App>,
    Query(range): Query<Range>,
    headers: HeaderMap,
) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_blocks(&app, &range, &headers).await;
    };
    match chain.window(&range, MAX_BLOCKS_PER_CALL) {
        Ok(window) if accepts(&headers, "application/octet-stream") => length_prefixed(window),
        Ok(window) => Json(BlocksPage {
            blocks: window.to_vec(),
        })
        .into_response(),
        Err(response) => response,
    }
}

async fn headers(State(app): State<App>, Query(range): Query<Range>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_headers(&app, &range).await;
    };
    match chain.window(&range, MAX_HEADERS_PER_CALL) {
        Ok(window) => Json(HeadersPage {
            headers: window
                .iter()
                .map(|block| HeaderView::from(&block.header))
                .collect(),
        })
        .into_response(),
        Err(response) => response,
    }
}

async fn tx(State(app): State<App>, UrlPath(key): UrlPath<String>, headers: HeaderMap) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_tx(&app, &headers, &key).await;
    };
    let Some(id) = parse::<TxId>(&key) else {
        return malformed("not a tx: id");
    };
    let Some(found) = chain.find(&id) else {
        return pending_tx(&app, &headers, id);
    };
    if !wants_json(&headers) {
        return borsh_of(&found.tx.tx);
    }
    Json(TxView {
        txid: id,
        status: TxStatus::Included,
        tx: found.tx.clone(),
        height: Some(Height(found.block.header.height.get())),
        index: u32::try_from(found.index).ok(),
        proof: found.proof.map(|proof| IncludedProof {
            eta: proof.eta,
            mask: proof.mask,
            proof_system: proof.proof_system,
            usage_counter: proof.usage_counter,
            proof: proof.proof.clone(),
            proof_hash: proof.proof_hash,
        }),
    })
    .into_response()
}

/// A transaction the chain does not hold: pending when it was submitted to the mock.
fn pending_tx(app: &App, headers: &HeaderMap, id: TxId) -> Response {
    let pending = app
        .pending
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&id)
        .cloned();
    let Some(tx) = pending else {
        return not_found("no such transaction");
    };
    if !wants_json(headers) {
        return borsh_of(&tx);
    }
    Json(TxView {
        txid: id,
        status: TxStatus::Pending,
        tx: SignedTxView::from(&tx),
        height: None,
        index: None,
        proof: None,
    })
    .into_response()
}

async fn inclusion(State(app): State<App>, UrlPath(key): UrlPath<String>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_inclusion(&app, &key).await;
    };
    let Some(id) = parse::<TxId>(&key) else {
        return malformed("not a tx: id");
    };
    let Some(found) = chain.find(&id) else {
        return not_found("no such transaction");
    };
    let leaves: Vec<_> = found
        .block
        .txs
        .iter()
        .map(|tx| tx.txid.hash())
        .chain(
            found
                .block
                .proof_txs
                .iter()
                .map(|proof| proof.proof_hash.hash()),
        )
        .collect();
    match inclusion_proof(&leaves, found.index) {
        Ok(path) => Json(InclusionProof {
            height: Height(found.block.header.height.get()),
            index: path.index,
            leaf_count: path.leaf_count,
            siblings: path.siblings,
        })
        .into_response(),
        Err(_) => not_found("no inclusion proof"),
    }
}

/// The registry entries of the `RegisterCircuit` txs of the chain.
fn circuits_of(chain: &Chain) -> Vec<CircuitEntry> {
    chain
        .all_txs()
        .filter_map(|(block, signed)| {
            let TxKind::RegisterCircuit {
                system,
                constraint_count,
                verifying_key,
                circuit,
            } = &signed.tx.body.kind
            else {
                return None;
            };
            Some(CircuitEntry {
                id: CircuitId(signed.txid),
                system: *system,
                constraint_count: *constraint_count,
                owner: signed.tx.body.sender,
                registered_at: Height(block.header.height.get()),
                verifying_key: verifying_key.clone(),
                circuit: circuit.clone(),
            })
        })
        .collect()
}

async fn circuits(State(app): State<App>, Query(include): Query<Include>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_circuits(&app, &include).await;
    };
    let keys = include.include.as_deref() == Some("keys");
    let entries: Vec<CircuitView> = circuits_of(chain)
        .iter()
        .map(|entry| CircuitView::new(entry, keys))
        .collect();
    Json(json!({ "circuits": entries })).into_response()
}

async fn circuit(
    State(app): State<App>,
    UrlPath(key): UrlPath<String>,
    Query(include): Query<Include>,
) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_circuit(&app, &key, &include).await;
    };
    let Some(id) = parse::<CircuitId>(&key) else {
        return malformed("not a circ: id");
    };
    let keys = include.include.as_deref() == Some("keys");
    match circuits_of(chain).iter().find(|entry| entry.id == id) {
        Some(entry) => Json(CircuitView::new(entry, keys)).into_response(),
        None => not_found("no such circuit"),
    }
}

async fn account(State(app): State<App>, UrlPath(key): UrlPath<String>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_account(&app, &key).await;
    };
    let Some(address) = parse::<Address>(&key) else {
        return malformed("not an addr: address");
    };
    let sent = chain
        .all_txs()
        .filter(|(_, signed)| signed.tx.body.sender == address)
        .count();
    let seen = sent > 0
        || chain.blocks.iter().any(|block| {
            block.header.miner == address
                || block.txs.iter().any(|signed| {
                    matches!(&signed.tx.body.kind, TxKind::Transfer { to, .. } if *to == address)
                })
        });
    if !seen {
        return not_found("the chain has not seen this address");
    }
    Json(AccountView {
        address,
        balance: Amount(MOCK_BALANCE),
        nonce: Nonce(u64::try_from(sent).unwrap_or(u64::MAX)),
    })
    .into_response()
}

async fn mempool(State(app): State<App>) -> Response {
    if app.chain.is_none() {
        return live_mempool(&app).await;
    }
    let pending = app.pending.lock().unwrap_or_else(PoisonError::into_inner);
    let requests = pending
        .values()
        .filter(|tx| matches!(tx.body.kind, TxKind::ProofRequest { .. }))
        .count();
    Json(MempoolView {
        tx_count: u32::try_from(pending.len()).unwrap_or(u32::MAX),
        proof_request_count: u32::try_from(requests).unwrap_or(u32::MAX),
        txids: pending.keys().copied().collect(),
    })
    .into_response()
}

/// One `block_accepted` event per block after genesis, `seq` equal to the height. No
/// long-poll: the answer is immediate.
async fn events(State(app): State<App>, Query(query): Query<EventsQuery>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return live_events(&app, &query).await;
    };
    let after = query.after.unwrap_or(0);
    let limit = usize::try_from(query.limit.unwrap_or(100).clamp(1, 1000)).unwrap_or(100);
    let events: Vec<Event> = chain
        .blocks
        .iter()
        .skip(1)
        .filter(|block| block.header.height.get() > after)
        .take(limit)
        .map(|block| Event {
            seq: block.header.height.get(),
            time: EventTime::now(),
            node_id: NodeId::default(),
            kind: EventKind::BlockAccepted(BlockAccepted {
                id: block.id,
                height: Height(block.header.height.get()),
                miner: block.header.miner,
                tx_count: u64::try_from(block.txs.len()).unwrap_or(u64::MAX),
                proof_count: u64::try_from(block.proof_txs.len()).unwrap_or(u64::MAX),
            }),
        })
        .collect();
    let next = events.last().map_or(after, |event| event.seq);
    Json(EventsPage { events, next }).into_response()
}

/// Checks the signature, keeps the transaction as pending in memory and acknowledges.
async fn submit_tx(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    if app.chain.is_none() {
        return live_submit(&app, &headers, &body).await;
    }
    let tx = match decode_tx(&headers, &body) {
        Ok(tx) => tx,
        Err(reason) => return malformed(&reason),
    };
    if let Err(reason) = verify_tx(&tx) {
        return error(ErrorClass::Rejected, "invalid_tx", &reason.to_string());
    }
    let id = txid(&tx);
    let included = app
        .chain
        .as_deref()
        .is_some_and(|chain| chain.find(&id).is_some());
    if !included {
        let mut pending = app.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending.len() >= MAX_PENDING && !pending.contains_key(&id) {
            return error(ErrorClass::Busy, code::BUSY, "the mock mempool is full");
        }
        pending.insert(id, tx);
    }
    (StatusCode::ACCEPTED, Json(SubmitTxResponse { txid: id })).into_response()
}

// ------------------------------------------------------------ node mode

/// Asks the node loop and waits for the answer, at most [`ASK_WAIT`]. A full queue is a
/// 503, and so is a loop that does not answer in time.
async fn ask<T>(
    app: &App,
    request: impl FnOnce(oneshot::Sender<T>) -> ApiRequest,
) -> Result<T, Response> {
    let (reply, answer) = oneshot::channel();
    submit(&app.api, request(reply)).map_err(refusal)?;
    match tokio::time::timeout(ASK_WAIT, answer).await {
        Ok(Ok(value)) => Ok(value),
        _ => Err(error(
            ErrorClass::Busy,
            code::BUSY,
            "the node did not answer in time",
        )),
    }
}

/// [`ask`] for a read of the store: a failed read is a 500 and is logged, not shown.
async fn read<T>(
    app: &App,
    request: impl FnOnce(oneshot::Sender<Result<T, StoreError>>) -> ApiRequest,
) -> Result<T, Response> {
    ask(app, request).await?.map_err(|fault| {
        warn!(%fault, "the store failed an API read");
        internal("the store cannot be read")
    })
}

fn json_or<T: Serialize>(result: Result<T, Response>) -> Response {
    match result {
        Ok(value) => Json(value).into_response(),
        Err(response) => response,
    }
}

/// A decimal height or a `blk:` id.
fn block_key(text: &str) -> Option<BlockKey> {
    if let Ok(height) = text.parse::<u64>() {
        return Some(BlockKey::Height(Height(height)));
    }
    parse::<BlockId>(text).map(BlockKey::Id)
}

/// The borsh blocks one after another, each prefixed by its length as a little-endian
/// u32, the format of [`length_prefixed`].
fn length_prefixed_bytes(items: &[BlockReply]) -> Response {
    let mut out = Vec::new();
    for item in items {
        let BlockReply::Bytes(bytes) = item else {
            return internal("a block came back as a view");
        };
        let Ok(len) = u32::try_from(bytes.len()) else {
            return internal("a block is over the u32 length prefix");
        };
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(bytes);
    }
    octets(out)
}

async fn live_tx(app: &App, headers: &HeaderMap, key: &str) -> Response {
    let Some(id) = parse::<TxId>(key) else {
        return malformed("not a tx: id");
    };
    let json = wants_json(headers);
    match read(app, |reply| ApiRequest::Tx { id, json, reply }).await {
        Ok(Some(TxReply::Bytes(bytes))) => octets(bytes),
        Ok(Some(TxReply::View(view))) => Json(view).into_response(),
        Ok(None) => not_found("no such transaction"),
        Err(response) => response,
    }
}

async fn live_inclusion(app: &App, key: &str) -> Response {
    let Some(id) = parse::<TxId>(key) else {
        return malformed("not a tx: id");
    };
    match read(app, |reply| ApiRequest::Inclusion { id, reply }).await {
        Ok(Some(proof)) => Json(proof).into_response(),
        Ok(None) => not_found("no such transaction in a block"),
        Err(response) => response,
    }
}

fn wants_keys(include: &Include) -> bool {
    include.include.as_deref() == Some("keys")
}

async fn live_circuits(app: &App, include: &Include) -> Response {
    let keys = wants_keys(include);
    match read(app, |reply| ApiRequest::Circuits { keys, reply }).await {
        Ok(entries) => Json(json!({ "circuits": entries })).into_response(),
        Err(response) => response,
    }
}

async fn live_circuit(app: &App, key: &str, include: &Include) -> Response {
    let Some(id) = parse::<CircuitId>(key) else {
        return malformed("not a circ: id");
    };
    let keys = wants_keys(include);
    match read(app, |reply| ApiRequest::Circuit { id, keys, reply }).await {
        Ok(Some(view)) => Json(view).into_response(),
        Ok(None) => not_found("no such circuit"),
        Err(response) => response,
    }
}

async fn live_node(app: &App) -> Response {
    json_or(read(app, |reply| ApiRequest::Node { reply }).await)
}

async fn live_header(app: &App, headers: &HeaderMap, key: Option<BlockKey>) -> Response {
    let Some(key) = key else {
        return not_found("no such block");
    };
    match read(app, |reply| ApiRequest::CanonicalHeader { key, reply }).await {
        Ok(Some(view)) => header_answer(headers, &view.header),
        Ok(None) => not_found("no such block"),
        Err(response) => response,
    }
}

async fn live_block(app: &App, headers: &HeaderMap, key: Option<BlockKey>) -> Response {
    let Some(key) = key else {
        return not_found("no such block");
    };
    let json = wants_json(headers);
    let request = |reply| ApiRequest::CanonicalBlock(Box::new(BlockQuery { key, json, reply }));
    match read(app, request).await {
        Ok(Some(BlockReply::Bytes(bytes))) => octets(bytes),
        Ok(Some(BlockReply::View(view))) => Json(view).into_response(),
        Ok(None) => not_found("no such block"),
        Err(response) => response,
    }
}

fn range_error(what: &Ranged<()>) -> Response {
    match what {
        Ranged::FromAboveTo => malformed("from is above to"),
        _ => error(
            ErrorClass::Rejected,
            code::RANGE_TOO_LARGE,
            "the range is over the cap of one call",
        ),
    }
}

async fn live_blocks(app: &App, range: &Range, headers: &HeaderMap) -> Response {
    let octet = accepts(headers, "application/octet-stream");
    let request = |reply| ApiRequest::Blocks {
        from: range.from,
        to: range.to,
        json: !octet,
        reply,
    };
    match read(app, request).await {
        Ok(Ranged::Items(items)) if octet => length_prefixed_bytes(&items),
        Ok(Ranged::Items(items)) => {
            let blocks = items
                .into_iter()
                .filter_map(|item| match item {
                    BlockReply::View(view) => Some(*view),
                    BlockReply::Bytes(_) => None,
                })
                .collect();
            Json(BlocksPage { blocks }).into_response()
        }
        Ok(Ranged::FromAboveTo) => range_error(&Ranged::FromAboveTo),
        Ok(Ranged::TooLarge) => range_error(&Ranged::TooLarge),
        Err(response) => response,
    }
}

async fn live_headers(app: &App, range: &Range) -> Response {
    let request = |reply| ApiRequest::Headers {
        from: range.from,
        to: range.to,
        reply,
    };
    match read(app, request).await {
        Ok(Ranged::Items(headers)) => Json(HeadersPage { headers }).into_response(),
        Ok(Ranged::FromAboveTo) => range_error(&Ranged::FromAboveTo),
        Ok(Ranged::TooLarge) => range_error(&Ranged::TooLarge),
        Err(response) => response,
    }
}

async fn live_account(app: &App, key: &str) -> Response {
    let Some(address) = parse::<Address>(key) else {
        return malformed("not an addr: address");
    };
    match read(app, |reply| ApiRequest::Account { address, reply }).await {
        Ok(Some(view)) => Json(view).into_response(),
        Ok(None) => not_found("the chain has not seen this address"),
        Err(response) => response,
    }
}

async fn live_mempool(app: &App) -> Response {
    json_or(ask(app, |reply| ApiRequest::Mempool { reply }).await)
}

/// 410 with the oldest retained `seq`, the body `node-events.md` gives an expired cursor.
fn cursor_expired(expired: CursorExpired) -> Response {
    let body = ErrorBody {
        error: ErrorDetail {
            code: code::CURSOR_EXPIRED.to_owned(),
            message: expired.to_string(),
            details: Some(ErrorDetails {
                oldest_seq: Some(expired.oldest_seq),
            }),
        },
    };
    (StatusCode::GONE, Json(body)).into_response()
}

/// How long `wait_ms` holds a request: none when absent, at most [`MAX_EVENTS_WAIT`].
fn events_wait(wait_ms: Option<u64>) -> Duration {
    Duration::from_millis(wait_ms.unwrap_or(0)).min(MAX_EVENTS_WAIT)
}

/// A page of the event log. A request that finds nothing new is held until there is news
/// or `wait_ms` is over, and asks the node loop again every [`EVENTS_POLL`]. The wait ends
/// with the empty page, whose `next` is `after`. A cursor that expires while waiting is
/// answered at once.
async fn live_events(app: &App, query: &EventsQuery) -> Response {
    let after = query.after.unwrap_or(0);
    let limit = query.limit.unwrap_or(100).clamp(1, 1000);
    let started = tokio::time::Instant::now();
    let deadline = started
        .checked_add(events_wait(query.wait_ms))
        .unwrap_or(started);
    loop {
        let asked = ask(app, |reply| ApiRequest::Events {
            after,
            limit,
            reply,
        })
        .await;
        match asked {
            Ok(Ok(page)) => {
                let now = tokio::time::Instant::now();
                if !page.events.is_empty() || now >= deadline {
                    return Json(page).into_response();
                }
                tokio::time::sleep(EVENTS_POLL.min(deadline.saturating_duration_since(now))).await;
            }
            Ok(Err(expired)) => return cursor_expired(expired),
            Err(response) => return response,
        }
    }
}

/// The body of `POST /v1/txs`: borsh, or JSON when the content type says so.
fn decode_tx(headers: &HeaderMap, body: &Bytes) -> Result<SignedTx, String> {
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    if json {
        serde_json::from_slice(body).map_err(|e| e.to_string())
    } else {
        borsh::from_slice(body).map_err(|e| e.to_string())
    }
}

fn accepted(id: TxId) -> Response {
    (StatusCode::ACCEPTED, Json(SubmitTxResponse { txid: id })).into_response()
}

/// A transaction the mempool does not take. A resubmission is accepted again, a pool that
/// is full is a 503, a transaction that can never fit or pay enough is a 422.
fn mempool_refusal(refused: &MempoolError) -> Response {
    let message = refused.to_string();
    match refused {
        MempoolError::Duplicate(id) => accepted(*id),
        MempoolError::Full { .. }
        | MempoolError::TooMany { .. }
        | MempoolError::SenderFull { .. } => error(ErrorClass::Busy, code::BUSY, &message),
        MempoolError::Underpriced { .. } => error(ErrorClass::Rejected, "underpriced", &message),
        MempoolError::OverRelayCap { .. } | MempoolError::Oversized { .. } => {
            error(ErrorClass::Rejected, "over_limit", &message)
        }
    }
}

/// Decodes the transaction, runs the stateless checks on this thread and hands the
/// verdict to the node loop, which pools it and gossips it.
async fn live_submit(app: &App, headers: &HeaderMap, body: &Bytes) -> Response {
    let tx = match decode_tx(headers, body) {
        Ok(tx) => tx,
        Err(reason) => return malformed(&reason),
    };
    let chain_id = match read(app, |reply| ApiRequest::Node { reply }).await {
        Ok(info) => info.chain_id,
        Err(response) => return response,
    };
    let checked = check_tx(tx, chain_id, &mut Scratch::default());
    let outcome = ask(app, |reply| ApiRequest::SubmitTx {
        checked: Box::new(checked),
        reply,
    })
    .await;
    match outcome {
        Ok(TxOutcome::Pooled(id)) => accepted(id),
        Ok(TxOutcome::Invalid(invalid)) => error(
            ErrorClass::Rejected,
            invalid.reason_code(),
            &invalid.to_string(),
        ),
        Ok(TxOutcome::Refused(refused)) => mempool_refusal(&refused),
        Err(response) => response,
    }
}

/// `POST /v1/txs` of a node whose loop listens on `api`: the status and the body of the
/// answer. The seam of the tests that run the handler against the real loop.
#[cfg(test)]
pub(crate) async fn post_tx(api: mpsc::Sender<ApiRequest>, body: Bytes) -> (StatusCode, Vec<u8>) {
    let app = App {
        chain: None,
        api,
        pending: PendingTxs::default(),
    };
    let response = submit_tx(State(app), HeaderMap::new(), body).await;
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, body.to_vec())
}

// ------------------------------------------------------------------ servers

fn api_router(app: App) -> Router {
    Router::new()
        .route(path::HEALTH, get(health))
        .route(path::NODE, get(node_info))
        .route(path::HEAD, get(head))
        .route(path::BLOCKS, get(blocks))
        .route(path::BLOCK, get(block))
        .route(path::BLOCK_HEADER, get(block_header))
        .route(path::HEADERS, get(headers))
        .route(path::TXS, post(submit_tx))
        .route(path::TX, get(tx))
        .route(path::TX_INCLUSION_PROOF, get(inclusion))
        .route(path::CIRCUITS, get(circuits))
        .route(path::CIRCUIT, get(circuit))
        .route(path::ACCOUNT, get(account))
        .route(path::MEMPOOL, get(mempool))
        .route(path::EVENTS, get(events))
        .with_state(app)
}

fn metrics_router(app: App) -> Router {
    Router::new()
        .route(path::METRICS, get(metrics))
        .with_state(app)
}

fn run(addr: SocketAddr, router: Router) -> Result<(), ComponentFault> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        info!(%addr, "serving HTTP");
        axum::serve(listener, router).await
    })?;
    Ok(())
}

/// Serves the API on `addr`, from the fixtures in `fixtures` when given.
pub fn serve_api(
    addr: SocketAddr,
    fixtures: Option<&Path>,
    api: &mpsc::Sender<ApiRequest>,
) -> Result<(), ComponentFault> {
    let chain = match fixtures {
        Some(dir) => Some(Arc::new(
            Chain::load(dir).map_err(ComponentFault::Fixtures)?,
        )),
        None => None,
    };
    run(
        addr,
        api_router(App {
            chain,
            api: api.clone(),
            pending: PendingTxs::default(),
        }),
    )
}

/// Serves `/metrics` on `addr`.
pub fn serve_metrics(
    addr: SocketAddr,
    api: &mpsc::Sender<ApiRequest>,
) -> Result<(), ComponentFault> {
    run(
        addr,
        metrics_router(App {
            chain: None,
            api: api.clone(),
            pending: PendingTxs::default(),
        }),
    )
}

#[cfg(test)]
mod tests;
