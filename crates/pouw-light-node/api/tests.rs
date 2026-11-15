use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
    thread,
};

use pouw_api::view::HeaderView;
use pouw_crypto::{Address, Hash32};
use pouw_types::{BlockHeader, BlockId, Target, U32, U64, block_id};
use serde_json::{Value, json};

use super::{LightApi, respond, serve};
use crate::headers::HeaderStore;

fn header(height: u64, parent: BlockId) -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(7),
        system_id: U64::new(0),
        height: U64::new(height),
        parent,
        timestamp: U64::new(1_000_u64.saturating_add(height)),
        miner: Address([0; 32]),
        tx_root: Hash32::ZERO,
        target: Target([0xff; 32]),
        nonce: U64::new(0),
    }
}

fn chain(count: u64) -> Vec<BlockHeader> {
    let mut headers = Vec::new();
    let mut parent = BlockId::ZERO;
    for height in 0..count {
        let next = header(height, parent);
        parent = block_id(&next);
        headers.push(next);
    }
    headers
}

fn path(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("pouw-api-{}-{name}.bin", std::process::id()));
    drop(fs::remove_file(&path));
    path
}

/// An API over a store holding `count` headers, with `cache` of them in memory.
fn api_with(name: &str, count: u64, cache: usize) -> (LightApi, Vec<BlockHeader>) {
    let headers = chain(count);
    let mut store = HeaderStore::open(&path(name), cache).unwrap();
    for next in &headers {
        store.push(*next).unwrap();
    }
    (LightApi::new(store), headers)
}

/// The status code and the body of the answer to `GET target`.
fn call(api: &LightApi, target: &str, json: bool) -> (u16, Vec<u8>) {
    let bytes = respond(api, &format!("GET {target} HTTP/1.1"), json);
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let head = String::from_utf8(bytes[..split].to_vec()).unwrap();
    let status = head.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, bytes[split.saturating_add(4)..].to_vec())
}

fn json_of(body: &[u8]) -> Value {
    serde_json::from_slice(body).unwrap()
}

fn error_code(body: &[u8]) -> Value {
    json_of(body)["error"]["code"].clone()
}

#[test]
fn the_head_is_the_tip_with_its_chain_id() {
    let (api, headers) = api_with("head", 5, 8);
    let (status, body) = call(&api, "/v1/light/head", true);
    assert_eq!(status, 200);
    let head = json_of(&body);
    assert_eq!(head["height"], json!(4));
    assert_eq!(head["chain_id"], json!(7));
    assert_eq!(
        head["id"],
        serde_json::to_value(block_id(&headers[4])).unwrap()
    );
}

#[test]
fn a_light_node_without_headers_has_no_head() {
    let api = LightApi::new(HeaderStore::open(&path("nohead"), 4).unwrap());
    let (status, body) = call(&api, "/v1/light/head", false);
    assert_eq!(status, 404);
    assert_eq!(error_code(&body), json!("unknown_block"));
    let (status, body) = call(&api, "/v1/headers", false);
    assert_eq!(status, 200);
    assert_eq!(json_of(&body)["headers"], json!([]));
}

#[test]
fn a_header_is_borsh_by_default_and_the_view_for_json_by_height_or_id() {
    let (api, headers) = api_with("header", 5, 8);
    let wanted = headers[3];
    let id = block_id(&wanted);

    let (status, body) = call(&api, "/v1/blocks/3/header", false);
    assert_eq!(status, 200);
    assert_eq!(borsh::to_vec(&wanted).unwrap(), body);

    let (status, body) = call(&api, "/v1/blocks/3/header", true);
    assert_eq!(status, 200);
    let view: HeaderView = serde_json::from_slice(&body).unwrap();
    assert_eq!(view, HeaderView::from(&wanted));

    let (status, body) = call(&api, &format!("/v1/blocks/{id}/header"), true);
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_slice::<HeaderView>(&body).unwrap().id, id);
}

#[test]
fn an_unknown_or_malformed_block_is_404_or_400() {
    let (api, _) = api_with("unknown", 3, 8);
    let (status, body) = call(&api, "/v1/blocks/9/header", true);
    assert_eq!(status, 404);
    assert_eq!(error_code(&body), json!("unknown_block"));
    let unknown = BlockId(Hash32([9; 32]));
    let (status, body) = call(&api, &format!("/v1/blocks/{unknown}/header"), true);
    assert_eq!(status, 404);
    assert_eq!(error_code(&body), json!("unknown_block"));
    let (status, body) = call(&api, "/v1/blocks/nonsense/header", true);
    assert_eq!(status, 400);
    assert_eq!(error_code(&body), json!("bad_request"));
}

#[test]
fn an_old_header_is_found_by_height_and_by_id() {
    let (api, headers) = api_with("old", 6, 2);
    let old = block_id(&headers[1]);
    let (status, _) = call(&api, "/v1/blocks/1/header", true);
    assert_eq!(status, 200);
    let (status, body) = call(&api, &format!("/v1/blocks/{old}/header"), true);
    assert_eq!(status, 200);
    assert_eq!(serde_json::from_slice::<HeaderView>(&body).unwrap().id, old);
}

#[test]
fn headers_come_in_ascending_order_from_a_range() {
    let (api, headers) = api_with("range", 6, 8);
    let (status, body) = call(&api, "/v1/headers?from=1&to=3", true);
    assert_eq!(status, 200);
    let page = json_of(&body);
    let ids: Vec<Value> = page["headers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|view| view["id"].clone())
        .collect();
    let expected: Vec<Value> = headers[1..=3]
        .iter()
        .map(|found| serde_json::to_value(block_id(found)).unwrap())
        .collect();
    assert_eq!(ids, expected);

    let (_, body) = call(&api, "/v1/headers", true);
    assert_eq!(json_of(&body)["headers"].as_array().unwrap().len(), 6);
    let (_, body) = call(&api, "/v1/headers?from=4", true);
    assert_eq!(json_of(&body)["headers"].as_array().unwrap().len(), 2);
    let (status, body) = call(&api, "/v1/headers?from=9", true);
    assert_eq!(status, 200);
    assert_eq!(json_of(&body)["headers"], json!([]));
}

#[test]
fn a_reversed_or_unparsable_range_is_400_and_an_oversized_one_is_422() {
    let (api, _) = api_with("big", 1_001, 8);
    let (status, body) = call(&api, "/v1/headers?from=3&to=1", true);
    assert_eq!(status, 400);
    assert_eq!(error_code(&body), json!("bad_request"));
    let (status, body) = call(&api, "/v1/headers?from=x", true);
    assert_eq!(status, 400);
    assert_eq!(error_code(&body), json!("bad_request"));

    let (status, body) = call(&api, "/v1/headers?from=0&to=1000", true);
    assert_eq!(status, 422);
    assert_eq!(error_code(&body), json!("range_too_large"));
    let (status, body) = call(&api, "/v1/headers?from=1&to=1000", true);
    assert_eq!(status, 200);
    assert_eq!(json_of(&body)["headers"].as_array().unwrap().len(), 1_000);
}

#[test]
fn health_other_routes_and_other_methods() {
    let (api, _) = api_with("misc", 2, 8);
    let (status, body) = call(&api, "/health", false);
    assert_eq!(status, 200);
    assert_eq!(json_of(&body), json!({"status": "ok"}));
    let (status, body) = call(&api, "/v1/nothing", false);
    assert_eq!(status, 404);
    assert_eq!(error_code(&body), json!("not_found"));

    let post = respond(&api, "POST /v1/light/head HTTP/1.1", false);
    assert!(post.starts_with(b"HTTP/1.1 405 "));
    assert!(respond(&api, "", false).starts_with(b"HTTP/1.1 400 "));
    assert!(respond(&api, "GET", false).starts_with(b"HTTP/1.1 400 "));
}

#[test]
fn the_server_answers_over_a_socket_and_reads_the_accept_header() {
    let (api, _) = api_with("socket", 3, 8);
    let api = Arc::new(api);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || serve(&listener, &api));

    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .write_all(
            b"GET /v1/blocks/2/header HTTP/1.1\r\nhost: x\r\nAccept: application/json\r\n\r\n",
        )
        .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    assert!(answer.contains("application/json"), "{answer}");
    assert!(answer.contains(r#""id":"blk:"#), "{answer}");
}
