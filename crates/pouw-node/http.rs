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
//!   it has in the chain. A submitted transaction is checked and acknowledged, not
//!   stored.
//! - **Node**: only `/health` is served; the other routes answer 501 until they are
//!   wired to the node loop through the api channel.
//!
//! `/metrics` always asks the node loop, whatever the mode.

#![allow(clippy::needless_pass_by_value, clippy::unused_async)]

use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Path as UrlPath, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use pouw_api::{
    error::{ErrorBody, ErrorClass, code},
    event::{BlockAccepted, Event, EventKind, EventTime, EventsPage, NodeId},
    path,
    view::{
        AccountView, BlockView, BlocksPage, CircuitView, HeaderView, HeadersPage, IncludedProof,
        InclusionProof, MAX_BLOCKS_PER_CALL, MAX_HEADERS_PER_CALL, MempoolView, NodeInfo,
        ProofTxView, SignedTxView, SubmitTxResponse, TxStatus, TxView,
    },
};
use pouw_crypto::Address;
use pouw_types::{
    Amount, BlockId, ChainId, CircuitEntry, CircuitId, Height, Nonce, SignedTx, TxId, TxKind,
    inclusion_proof, txid, verify_tx,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tracing::info;

use crate::{
    api::{ApiRequest, Refused, submit},
    node::ComponentFault,
};

/// The balance every address of the fixture chain has in fixtures mode.
pub const MOCK_BALANCE: u64 = 1_000_000;

/// How long `/metrics` waits for the node loop.
const METRICS_WAIT: Duration = Duration::from_secs(5);

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

fn not_implemented() -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Json(ErrorBody::new(
            "not_implemented",
            "this route is served from fixtures only, set POUW_API_FIXTURES (pouw-node#59)",
        )),
    )
        .into_response()
}

fn refusal(refused: Refused) -> Response {
    error(ErrorClass::Busy, code::BUSY, &refused.to_string())
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
        return not_implemented();
    };
    Json(NodeInfo {
        chain_id: chain.chain_id,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        height: Height(chain.tip_height()),
        peers: 0,
    })
    .into_response()
}

async fn head(State(app): State<App>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return not_implemented();
    };
    Json(HeaderView::from(&chain.tip().header)).into_response()
}

async fn block(State(app): State<App>, UrlPath(key): UrlPath<String>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return not_implemented();
    };
    match chain.block(&key) {
        Some(block) => Json(block).into_response(),
        None => not_found("no such block"),
    }
}

async fn block_header(State(app): State<App>, UrlPath(key): UrlPath<String>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return not_implemented();
    };
    match chain.block(&key) {
        Some(block) => Json(HeaderView::from(&block.header)).into_response(),
        None => not_found("no such block"),
    }
}

async fn blocks(State(app): State<App>, Query(range): Query<Range>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return not_implemented();
    };
    match chain.window(&range, MAX_BLOCKS_PER_CALL) {
        Ok(window) => Json(BlocksPage {
            blocks: window.to_vec(),
        })
        .into_response(),
        Err(response) => response,
    }
}

async fn headers(State(app): State<App>, Query(range): Query<Range>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return not_implemented();
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

async fn tx(State(app): State<App>, UrlPath(key): UrlPath<String>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return not_implemented();
    };
    let Some(id) = parse::<TxId>(&key) else {
        return malformed("not a tx: id");
    };
    let Some(found) = chain.find(&id) else {
        return not_found("no such transaction");
    };
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

async fn inclusion(State(app): State<App>, UrlPath(key): UrlPath<String>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return not_implemented();
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
        return not_implemented();
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
        return not_implemented();
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
        return not_implemented();
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
        return not_implemented();
    }
    Json(MempoolView {
        tx_count: 0,
        proof_request_count: 0,
        txids: Vec::new(),
    })
    .into_response()
}

/// One `block_accepted` event per block after genesis, `seq` equal to the height. No
/// long-poll: the answer is immediate.
async fn events(State(app): State<App>, Query(query): Query<EventsQuery>) -> Response {
    let Some(chain) = app.chain.as_deref() else {
        return not_implemented();
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

/// Checks the signature and acknowledges; nothing is stored.
async fn submit_tx(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    if app.chain.is_none() {
        return not_implemented();
    }
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/json"));
    let decoded: Result<SignedTx, String> = if json {
        serde_json::from_slice(&body).map_err(|e| e.to_string())
    } else {
        borsh::from_slice(&body).map_err(|e| e.to_string())
    };
    let tx = match decoded {
        Ok(tx) => tx,
        Err(reason) => return malformed(&reason),
    };
    if let Err(reason) = verify_tx(&tx) {
        return error(ErrorClass::Rejected, "invalid_tx", &reason.to_string());
    }
    (
        StatusCode::ACCEPTED,
        Json(SubmitTxResponse { txid: txid(&tx) }),
    )
        .into_response()
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
        }),
    )
}
