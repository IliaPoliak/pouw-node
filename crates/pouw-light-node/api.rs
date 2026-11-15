//! The read API of the light node (`contracts/light-node-api.md`), served over plain
//! HTTP/1.1 on the API address, one request per connection.
//!
//! Answered from the header store: `GET /v1/light/head`,
//! `GET /v1/blocks/{height_or_hash}/header` and `GET /v1/headers?from=&to=`, and
//! `GET /health`. Asked of a full node (`POUW_FULL_NODES`) and passed on: the block,
//! `GET /v1/accounts/{addr}`, `GET /v1/txs/{txid}` and its `/inclusion-proof`.
//! `GET /v1/light/proof-jobs/{txid}` is built from the tx of a full node and the
//! headers of the store, and an included job is reported only when the inclusion proof
//! of the full node verifies against the `tx_root` of the header the store holds at that
//! height (`upstream_invalid` otherwise).
//!
//! A header is borsh by default and the JSON view when `Accept` names `application/json`,
//! as in the full node API.
//!
//! A header is found by its height or by its `blk:` id at any depth, the store keeps
//! an index of the ids.
//!
//! Errors have the shape `{"error": {"code", "message"}}` with the codes of the light
//! contract: `bad_request` (400), `unknown_block`, `unknown_account`, `unknown_tx` and
//! `unknown_proof_job` (404), `range_too_large` (422). A full node that cannot be reached
//! is 502 `upstream_unavailable`. An id is checked before any full node is asked, so a
//! request never carries text of the client into the path.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, PoisonError, RwLock},
    thread,
    time::Duration,
};

use pouw_api::{
    error::{ErrorBody, code},
    path::{HEADERS, HEALTH},
    view::{HeaderView, HeadersPage, InclusionProof, MAX_HEADERS_PER_CALL, TxStatus, TxView},
};
use pouw_crypto::Address;
use pouw_types::{
    BlockHeader, BlockId, ChainId, Height, ProofHash, ProofTx, TxId, TxKind, block_id,
    proof_tx_hash, txid as txid_of, verify_inclusion,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use tracing::{debug, warn};

use crate::{
    headers::{HeaderStore, StoreError},
    upstream::{Answer, Upstream},
};

const LIGHT_HEAD: &str = "/v1/light/head";
const BAD_REQUEST: &str = "bad_request";
const UNKNOWN_BLOCK: &str = "unknown_block";
const UNKNOWN_ACCOUNT: &str = "unknown_account";
const UNKNOWN_TX: &str = "unknown_tx";
const UNKNOWN_PROOF_JOB: &str = "unknown_proof_job";

const JSON: &str = "application/json";
const OCTETS: &str = "application/octet-stream";

/// Most bytes of a request head the server reads.
const MAX_HEAD_BYTES: u64 = 8192;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// What the light node serves: the header store behind a lock and the full nodes it asks
/// for the rest. The sync writes through [`LightApi::store`], the routes read.
#[derive(Debug)]
pub struct LightApi {
    store: RwLock<HeaderStore>,
    upstream: Upstream,
}

impl LightApi {
    pub fn new(store: HeaderStore, upstream: Upstream) -> Self {
        Self {
            store: RwLock::new(store),
            upstream,
        }
    }

    pub fn store(&self) -> &RwLock<HeaderStore> {
        &self.store
    }

    /// Runs `read` on the store. A failed read is a 500 that is logged, not shown.
    fn read<T>(
        &self,
        read: impl FnOnce(&HeaderStore) -> Result<T, StoreError>,
    ) -> Result<T, Reply> {
        let guard = self.store.read().unwrap_or_else(PoisonError::into_inner);
        read(&guard).map_err(|error| {
            warn!(%error, "the header store cannot be read");
            Reply::internal()
        })
    }
}

/// `GET /v1/light/head`.
#[derive(Debug, Serialize)]
struct LightHead {
    chain_id: ChainId,
    height: Height,
    id: BlockId,
}

struct Reply {
    status: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Reply {
    fn json<T: Serialize>(value: &T) -> Self {
        match serde_json::to_vec(value) {
            Ok(body) => Self {
                status: "200 OK",
                content_type: JSON,
                body,
            },
            Err(_) => Self::internal(),
        }
    }

    fn octets(body: Vec<u8>) -> Self {
        Self {
            status: "200 OK",
            content_type: OCTETS,
            body,
        }
    }

    fn error(status: &'static str, code: &str, message: &str) -> Self {
        let body = serde_json::to_vec(&ErrorBody::new(code, message)).unwrap_or_default();
        Self {
            status,
            content_type: JSON,
            body,
        }
    }

    fn bad_request(message: &str) -> Self {
        Self::error("400 Bad Request", BAD_REQUEST, message)
    }

    fn not_found(code: &str, message: &str) -> Self {
        Self::error("404 Not Found", code, message)
    }

    fn bad_gateway() -> Self {
        Self::error(
            "502 Bad Gateway",
            "upstream_unavailable",
            "no full node answered",
        )
    }

    fn invalid_upstream() -> Self {
        Self::error(
            "502 Bad Gateway",
            "upstream_invalid",
            "the answer of the full node does not match the request or the header of the light node",
        )
    }

    fn internal() -> Self {
        Self::error(
            "500 Internal Server Error",
            "internal",
            "the header store cannot be read",
        )
    }

    fn to_bytes(&self) -> Vec<u8> {
        let head = format!(
            "HTTP/1.1 {}\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            self.status,
            self.content_type,
            self.body.len()
        );
        let mut out = head.into_bytes();
        out.extend_from_slice(&self.body);
        out
    }
}

/// A block of the URL: a decimal height or a `blk:` id.
enum Key {
    Height(Height),
    Id(BlockId),
}

fn block_key(text: &str) -> Option<Key> {
    if let Ok(height) = text.parse::<u64>() {
        return Some(Key::Height(Height(height)));
    }
    serde_json::from_value::<BlockId>(Value::String(text.to_owned()))
        .ok()
        .map(Key::Id)
}

/// `text` as a `T` and back as text, so that only the canonical form of an id reaches a
/// full node.
fn typed<T: Serialize + DeserializeOwned>(text: &str) -> Option<String> {
    let value: T = serde_json::from_value(Value::String(text.to_owned())).ok()?;
    serde_json::to_value(&value)
        .ok()?
        .as_str()
        .map(str::to_owned)
}

/// What a full node answered, as the light node answers it: a 200 as it is, a 404 with
/// the code `missing` of the route, a 400 as `bad_request`, anything else is 502.
fn forwarded(answer: Answer, missing: &str) -> Reply {
    match answer.status {
        200 => Reply {
            status: "200 OK",
            content_type: if answer.content_type.contains(JSON) {
                JSON
            } else {
                OCTETS
            },
            body: answer.body,
        },
        404 => Reply::not_found(missing, "not known to the full node"),
        400 => Reply::bad_request("the full node does not accept the request"),
        status => {
            warn!(status, "unexpected answer of a full node");
            Reply::bad_gateway()
        }
    }
}

fn forward(api: &LightApi, path: &str, json: bool, missing: &str) -> Reply {
    match api.upstream.get(path, json) {
        Ok(answer) => forwarded(answer, missing),
        Err(error) => {
            warn!(%error, path, "cannot ask a full node");
            Reply::bad_gateway()
        }
    }
}

/// `GET /v1/blocks/{height_or_hash}`.
fn block(api: &LightApi, key: &str, json: bool) -> Reply {
    let path = match block_key(key) {
        None => return Reply::bad_request("not a height or a blk: id"),
        Some(Key::Height(height)) => format!("/v1/blocks/{}", height.0),
        Some(Key::Id(id)) => format!("/v1/blocks/{id}"),
    };
    forward(api, &path, json, UNKNOWN_BLOCK)
}

/// `GET /v1/accounts/{addr}`.
fn account(api: &LightApi, addr: &str, json: bool) -> Reply {
    match typed::<Address>(addr) {
        Some(addr) => forward(api, &format!("/v1/accounts/{addr}"), json, UNKNOWN_ACCOUNT),
        None => Reply::bad_request("not an address"),
    }
}

/// `GET /v1/txs/{txid}` and, with `suffix`, `/inclusion-proof`.
fn tx(api: &LightApi, txid: &str, suffix: &str, json: bool) -> Reply {
    match typed::<TxId>(txid) {
        Some(txid) => forward(api, &format!("/v1/txs/{txid}{suffix}"), json, UNKNOWN_TX),
        None => Reply::bad_request("not a tx: id"),
    }
}

/// `GET /v1/light/proof-jobs/{txid}`, the status of a proof request. It is read from the
/// tx view of a full node; the block of an included request is the header of that
/// height among the headers the light node holds.
#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum ProofJob {
    Pending {
        txid: TxId,
    },
    Included {
        txid: TxId,
        proof_hash: ProofHash,
        height: Height,
        block: BlockId,
    },
}

/// Asks a full node for the inclusion proof of `txid` and checks it against the
/// `tx_root` of `header`, the header the light node holds at `height`. A full node on
/// another chain, or one that lies, cannot make the light node report a block that never
/// held the proof.
fn check_inclusion(
    api: &LightApi,
    txid: &str,
    height: Height,
    index: Option<u32>,
    header: &BlockHeader,
    leaf: &ProofHash,
) -> Result<(), Reply> {
    let answer = api
        .upstream
        .get(&format!("/v1/txs/{txid}/inclusion-proof"), true)
        .map_err(|error| {
            warn!(%error, "cannot ask a full node");
            Reply::bad_gateway()
        })?;
    let valid = answer.status == 200
        && serde_json::from_slice::<InclusionProof>(&answer.body).is_ok_and(|proof| {
            proof.height == height
                && Some(proof.index) == index
                && verify_inclusion(
                    &header.tx_root,
                    &leaf.0,
                    proof.index,
                    proof.leaf_count,
                    &proof.siblings,
                )
        });
    if valid {
        Ok(())
    } else {
        warn!(%txid, "the inclusion proof of a full node does not match the local header");
        Err(Reply::invalid_upstream())
    }
}

fn proof_job(api: &LightApi, txid: &str) -> Reply {
    let Some(txid) = typed::<TxId>(txid) else {
        return Reply::bad_request("not a tx: id");
    };
    let answer = match api.upstream.get(&format!("/v1/txs/{txid}"), true) {
        Ok(answer) => answer,
        Err(error) => {
            warn!(%error, "cannot ask a full node");
            return Reply::bad_gateway();
        }
    };
    if answer.status != 200 {
        return forwarded(answer, UNKNOWN_PROOF_JOB);
    }
    let Ok(view) = serde_json::from_slice::<TxView>(&answer.body) else {
        warn!("a full node answered a tx that does not parse");
        return Reply::bad_gateway();
    };
    // the answer must be about the tx that was asked for, whatever ids it carries
    if view.txid.to_string() != txid
        || view.tx.txid.to_string() != txid
        || txid_of(&view.tx.tx).to_string() != txid
    {
        warn!(%txid, "a full node answered about another tx");
        return Reply::invalid_upstream();
    }
    if !matches!(view.tx.tx.body.kind, TxKind::ProofRequest { .. }) {
        return Reply::not_found(UNKNOWN_PROOF_JOB, "not a proof request");
    }
    let job = match (view.status, view.height, view.proof) {
        (TxStatus::Pending, _, _) => ProofJob::Pending { txid: view.txid },
        (TxStatus::Included, Some(height), Some(proof)) => {
            // the proof hash is the leaf of the proof tx, which holds this request: it
            // is computed from what the answer says and must be the one it claims
            let proof_tx = ProofTx {
                request: view.tx.tx.clone(),
                usage_counter: proof.usage_counter,
                proof: proof.proof.clone(),
            };
            if proof_tx_hash(&proof_tx) != proof.proof_hash {
                warn!(%txid, "the proof hash of a full node is not the hash of its proof tx");
                return Reply::invalid_upstream();
            }
            let held = match api.read(|store| store.get(height)) {
                Ok(Some(held)) => held,
                Ok(None) => {
                    return Reply::not_found(
                        UNKNOWN_BLOCK,
                        "the light node does not hold the block of this proof yet",
                    );
                }
                Err(reply) => return reply,
            };
            if let Err(reply) =
                check_inclusion(api, &txid, height, view.index, &held, &proof.proof_hash)
            {
                return reply;
            }
            ProofJob::Included {
                txid: view.txid,
                proof_hash: proof.proof_hash,
                height,
                block: block_id(&held),
            }
        }
        (TxStatus::Included, _, _) => {
            warn!("a full node answered an included proof request without its proof");
            return Reply::bad_gateway();
        }
    };
    Reply::json(&job)
}

/// The routes with an id in the path.
fn with_id(api: &LightApi, path: &str, json: bool) -> Reply {
    if let Some(rest) = path.strip_prefix("/v1/blocks/") {
        return match rest.strip_suffix("/header") {
            Some(key) => header(api, key, json),
            None => block(api, rest, json),
        };
    }
    if let Some(addr) = path.strip_prefix("/v1/accounts/") {
        return account(api, addr, json);
    }
    if let Some(rest) = path.strip_prefix("/v1/txs/") {
        return match rest.strip_suffix("/inclusion-proof") {
            Some(txid) => tx(api, txid, "/inclusion-proof", json),
            None => tx(api, rest, "", json),
        };
    }
    if let Some(txid) = path.strip_prefix("/v1/light/proof-jobs/") {
        return proof_job(api, txid);
    }
    Reply::not_found(code::NOT_FOUND, "no such route")
}

fn head(api: &LightApi) -> Reply {
    let answer = api.read(|store| -> Result<Option<LightHead>, StoreError> {
        let Some((height, hash)) = store.tip() else {
            return Ok(None);
        };
        Ok(store.get(height)?.map(|header| LightHead {
            chain_id: ChainId(header.chain_id.get()),
            height,
            id: hash,
        }))
    });
    match answer {
        Ok(Some(head)) => Reply::json(&head),
        Ok(None) => Reply::not_found(UNKNOWN_BLOCK, "the light node holds no headers yet"),
        Err(reply) => reply,
    }
}

fn header(api: &LightApi, key: &str, json: bool) -> Reply {
    let found = match block_key(key) {
        None => return Reply::bad_request("not a height or a blk: id"),
        Some(Key::Height(height)) => api.read(|store| store.get(height)),
        Some(Key::Id(id)) => api.read(|store| store.find(&id)),
    };
    let header: BlockHeader = match found {
        Ok(Some(header)) => header,
        Ok(None) => return Reply::not_found(UNKNOWN_BLOCK, "no such block"),
        Err(reply) => return reply,
    };
    if json {
        return Reply::json(&HeaderView::from(&header));
    }
    borsh::to_vec(&header).map_or_else(|_| Reply::internal(), Reply::octets)
}

/// The values of `from` and `to` in a query string, `None` when one does not parse.
fn parse_range(query: &str) -> Option<(Option<u64>, Option<u64>)> {
    let (mut from, mut to) = (None, None);
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        match name {
            "from" => from = Some(value.parse().ok()?),
            "to" => to = Some(value.parse().ok()?),
            _ => {}
        }
    }
    Some((from, to))
}

fn headers(api: &LightApi, query: &str) -> Reply {
    let Some((from, to)) = parse_range(query) else {
        return Reply::bad_request("from and to are decimal heights");
    };
    let tip = match api.read(|store| Ok(store.tip())) {
        Ok(tip) => tip.map(|(height, _)| height.0),
        Err(reply) => return reply,
    };
    let empty = || {
        Reply::json(&HeadersPage {
            headers: Vec::new(),
        })
    };
    let Some(tip) = tip else {
        return empty();
    };
    let from = from.unwrap_or(0);
    let to = to.unwrap_or(tip).min(tip);
    if from > tip {
        return empty();
    }
    if from > to {
        return Reply::bad_request("from is above to");
    }
    if to.saturating_sub(from) >= MAX_HEADERS_PER_CALL {
        return Reply::error(
            "422 Unprocessable Content",
            code::RANGE_TOO_LARGE,
            &format!("at most {MAX_HEADERS_PER_CALL} headers in one call"),
        );
    }
    let views = api.read(|store| {
        let mut views = Vec::new();
        for height in from..=to {
            if let Some(found) = store.get(Height(height))? {
                views.push(HeaderView::from(&found));
            }
        }
        Ok(views)
    });
    match views {
        Ok(headers) => Reply::json(&HeadersPage { headers }),
        Err(reply) => reply,
    }
}

fn route(api: &LightApi, request_line: &str, json: bool) -> Reply {
    let mut parts = request_line.split_whitespace();
    let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
        return Reply::bad_request("not a request line");
    };
    if method != "GET" {
        return Reply::error(
            "405 Method Not Allowed",
            "method_not_allowed",
            "the light API is read-only",
        );
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    match path {
        HEALTH => Reply {
            status: "200 OK",
            content_type: JSON,
            body: br#"{"status":"ok"}"#.to_vec(),
        },
        LIGHT_HEAD => head(api),
        HEADERS => headers(api, query),
        other => with_id(api, other, json),
    }
}

/// The full HTTP response for a request line such as `GET /health HTTP/1.1`. `json` is
/// whether the request names `application/json` in its `Accept` header.
pub fn respond(api: &LightApi, request_line: &str, json: bool) -> Vec<u8> {
    route(api, request_line, json).to_bytes()
}

/// Accepts connections until the process ends, one thread per connection.
pub fn serve(listener: &TcpListener, api: &Arc<LightApi>) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let api = Arc::clone(api);
                thread::spawn(move || {
                    if let Err(error) = handle(&api, stream) {
                        debug!(%error, "API connection failed");
                    }
                });
            }
            Err(error) => warn!(%error, "cannot accept a connection"),
        }
    }
}

fn handle(api: &LightApi, mut stream: TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    let (request_line, json) = read_head(&stream)?;
    stream.write_all(&respond(api, &request_line, json))
}

/// The request line and whether `Accept` names JSON. The headers are read to the end so
/// that closing the connection does not reset it before the client reads the answer.
fn read_head(stream: &TcpStream) -> io::Result<(String, bool)> {
    let mut reader = BufReader::new(stream.take(MAX_HEAD_BYTES));
    let mut first = String::new();
    reader.read_line(&mut first)?;
    let mut json = false;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 || line.trim_end().is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':')
            && name.trim().eq_ignore_ascii_case("accept")
            && value.contains(JSON)
        {
            json = true;
        }
    }
    Ok((first.trim_end().to_owned(), json))
}

#[cfg(test)]
mod tests;
