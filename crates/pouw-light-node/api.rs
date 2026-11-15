//! The read API of the light node (`contracts/light-node-api.md`), served over plain
//! HTTP/1.1 on the API address, one request per connection.
//!
//! Answered from the header store: `GET /v1/light/head`,
//! `GET /v1/blocks/{height_or_hash}/header` and `GET /v1/headers?from=&to=`, and
//! `GET /health`. A header is borsh by default and the JSON view when `Accept` names
//! `application/json`, as in the full node API.
//!
//! The light node keeps no index by id, so a header is found by its `blk:` id only
//! while it is among the last N headers in memory; any header is found by its height.
//!
//! Errors have the shape `{"error": {"code", "message"}}` with the codes of the light
//! contract: `bad_request` (400), `unknown_block` (404), `range_too_large` (422).

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
    view::{HeaderView, HeadersPage, MAX_HEADERS_PER_CALL},
};
use pouw_types::{BlockHeader, BlockId, ChainId, Height};
use serde::Serialize;
use serde_json::Value;
use tracing::{debug, warn};

use crate::headers::{HeaderStore, StoreError};

const LIGHT_HEAD: &str = "/v1/light/head";
const BAD_REQUEST: &str = "bad_request";
const UNKNOWN_BLOCK: &str = "unknown_block";

const JSON: &str = "application/json";
const OCTETS: &str = "application/octet-stream";

/// Most bytes of a request head the server reads.
const MAX_HEAD_BYTES: u64 = 8192;
const IO_TIMEOUT: Duration = Duration::from_secs(2);

/// What the light node serves: the header store behind a lock. The sync writes through
/// [`LightApi::store`], the routes read.
#[derive(Debug)]
pub struct LightApi {
    store: RwLock<HeaderStore>,
}

impl LightApi {
    pub fn new(store: HeaderStore) -> Self {
        Self {
            store: RwLock::new(store),
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
    hash: BlockId,
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

fn head(api: &LightApi) -> Reply {
    let answer = api.read(|store| -> Result<Option<LightHead>, StoreError> {
        let Some((height, hash)) = store.tip() else {
            return Ok(None);
        };
        Ok(store.get(height)?.map(|header| LightHead {
            chain_id: ChainId(header.chain_id.get()),
            height,
            hash,
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
        Some(Key::Id(id)) => api.read(|store| Ok(store.find(&id))),
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
        other => match other
            .strip_prefix("/v1/blocks/")
            .and_then(|rest| rest.strip_suffix("/header"))
        {
            Some(key) => header(api, key, json),
            None => Reply::not_found(code::NOT_FOUND, "no such route"),
        },
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
