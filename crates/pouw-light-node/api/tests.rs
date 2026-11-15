use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
    thread,
};

use pouw_api::view::{HeaderView, IncludedProof, InclusionProof, SignedTxView, TxStatus, TxView};
use pouw_crypto::{Address, FieldInput, Hash32, Signature};
use pouw_types::{
    Amount, BlockHeader, BlockId, ChainId, CircuitId, Height, Nonce, ProofHash, ProofSystem,
    SignedTx, Target, TxBody, TxId, TxKind, U32, U64, UsageCounter, block_id, bound_root,
    inclusion_proof, leaf_count_u32, merkle_root,
};
use serde_json::{Value, json};

use super::{LightApi, respond, serve};
use crate::{
    headers::HeaderStore,
    upstream::{
        Upstream,
        tests::{dead_node, fake_node, http},
    },
};

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
    (LightApi::new(store, Upstream::default()), headers)
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
    let api = LightApi::new(
        HeaderStore::open(&path("nohead"), 4).unwrap(),
        Upstream::default(),
    );
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

fn text<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn request() -> SignedTx {
    SignedTx {
        body: TxBody {
            chain_id: ChainId(7),
            sender: Address([0x11; 32]),
            nonce: Nonce(4),
            fee: Amount(120),
            kind: TxKind::ProofRequest {
                circuit: CircuitId(TxId(Hash32([0x22; 32]))),
                public_inputs: vec![FieldInput([3; 31])],
                witness: Box::from([1, 2, 3]),
            },
        },
        signature: Signature([9; 64]),
    }
}

fn transfer() -> SignedTx {
    SignedTx {
        body: TxBody {
            chain_id: ChainId(7),
            sender: Address([0x11; 32]),
            nonce: Nonce(5),
            fee: Amount(1),
            kind: TxKind::Transfer {
                to: Address([0x33; 32]),
                amount: Amount(10),
            },
        },
        signature: Signature([9; 64]),
    }
}

/// The JSON of `GET /v1/txs/{txid}` for `tx`, included at `height` or pending.
fn tx_view(tx: &SignedTx, height: Option<u64>) -> Vec<u8> {
    let signed = SignedTxView::from(tx);
    let view = match height {
        None => TxView {
            txid: signed.txid,
            status: TxStatus::Pending,
            tx: signed,
            height: None,
            index: None,
            proof: None,
        },
        Some(height) => TxView {
            txid: signed.txid,
            status: TxStatus::Included,
            tx: signed,
            height: Some(Height(height)),
            index: Some(0),
            proof: Some(IncludedProof {
                eta: FieldInput([1; 31]),
                mask: FieldInput([2; 31]),
                proof_system: ProofSystem::PlonkKzg,
                usage_counter: UsageCounter(1),
                proof: Box::from([4, 5]),
                proof_hash: ProofHash(Hash32([5; 32])),
            }),
        },
    };
    serde_json::to_vec(&view).unwrap()
}

/// An API over `count` headers whose full node is the one at `url`.
fn api_asking(name: &str, count: u64, url: &str) -> (LightApi, Vec<BlockHeader>) {
    let (mut api, headers) = api_with(name, count, 8);
    api.upstream = Upstream::new(&[url.to_owned()]);
    (api, headers)
}

#[test]
fn a_block_an_account_a_tx_and_an_inclusion_proof_are_asked_of_the_full_node() {
    let account = text(&Address([0x11; 32]));
    let txid = text(&SignedTxView::from(&request()).txid);
    let answers = vec![
        http("200 OK", "application/json", br#"{"block":1}"#),
        http("200 OK", "application/json", br#"{"account":1}"#),
        http("200 OK", "application/json", br#"{"tx":1}"#),
        http("200 OK", "application/json", br#"{"proof":1}"#),
    ];
    let (url, node) = fake_node(answers);
    let (api, _) = api_asking("forward", 2, &url);

    let (status, body) = call(&api, "/v1/blocks/3", true);
    assert_eq!((status, json_of(&body)), (200, json!({"block": 1})));
    let (status, body) = call(&api, &format!("/v1/accounts/{account}"), true);
    assert_eq!((status, json_of(&body)), (200, json!({"account": 1})));
    let (status, body) = call(&api, &format!("/v1/txs/{txid}"), true);
    assert_eq!((status, json_of(&body)), (200, json!({"tx": 1})));
    let (status, body) = call(&api, &format!("/v1/txs/{txid}/inclusion-proof"), true);
    assert_eq!((status, json_of(&body)), (200, json!({"proof": 1})));

    let requests = node.join().unwrap();
    let lines: Vec<&str> = requests
        .iter()
        .map(|request| request.lines().next().unwrap())
        .collect();
    assert_eq!(
        lines,
        [
            "GET /v1/blocks/3 HTTP/1.0".to_owned(),
            format!("GET /v1/accounts/{account} HTTP/1.0"),
            format!("GET /v1/txs/{txid} HTTP/1.0"),
            format!("GET /v1/txs/{txid}/inclusion-proof HTTP/1.0"),
        ]
    );
}

#[test]
fn a_block_is_asked_of_the_full_node_by_id_and_borsh_passes_through() {
    let (url, node) = fake_node(vec![http("200 OK", "application/octet-stream", &[7, 8, 9])]);
    let (api, headers) = api_asking("blockid", 2, &url);
    let id = text(&block_id(&headers[1]));
    let (status, body) = call(&api, &format!("/v1/blocks/{id}"), false);
    assert_eq!((status, body), (200, vec![7, 8, 9]));
    let requests = node.join().unwrap();
    assert!(requests[0].starts_with(&format!("GET /v1/blocks/{id} HTTP/1.0")));
    assert!(requests[0].contains("accept: application/octet-stream"));
}

#[test]
fn a_404_of_the_full_node_becomes_the_code_of_the_route() {
    let missing = || {
        http(
            "404 Not Found",
            "application/json",
            br#"{"error":{"code":"not_found","message":"x"}}"#,
        )
    };
    let (url, node) = fake_node(vec![missing(), missing(), missing(), missing()]);
    let (api, _) = api_asking("missing", 2, &url);
    let account = text(&Address([0x11; 32]));
    let txid = text(&SignedTxView::from(&request()).txid);

    let (status, body) = call(&api, "/v1/blocks/9", true);
    assert_eq!((status, error_code(&body)), (404, json!("unknown_block")));
    let (status, body) = call(&api, &format!("/v1/accounts/{account}"), true);
    assert_eq!((status, error_code(&body)), (404, json!("unknown_account")));
    let (status, body) = call(&api, &format!("/v1/txs/{txid}"), true);
    assert_eq!((status, error_code(&body)), (404, json!("unknown_tx")));
    let (status, body) = call(&api, &format!("/v1/txs/{txid}/inclusion-proof"), true);
    assert_eq!((status, error_code(&body)), (404, json!("unknown_tx")));
    node.join().unwrap();
}

#[test]
fn a_malformed_id_is_400_before_the_full_node_is_asked() {
    let (api, _) = api_with("malformed", 2, 8);
    for target in [
        "/v1/blocks/zzz",
        "/v1/accounts/zzz",
        "/v1/txs/zzz",
        "/v1/txs/zzz/inclusion-proof",
        "/v1/light/proof-jobs/zzz",
        "/v1/txs/../accounts/x",
    ] {
        let (status, body) = call(&api, target, true);
        assert_eq!(status, 400, "{target}");
        assert_eq!(error_code(&body), json!("bad_request"), "{target}");
    }
}

#[test]
fn without_a_full_node_the_forwarded_routes_are_502_and_the_header_routes_still_work() {
    let (api, _) = api_with("nofull", 3, 8);
    let account = text(&Address([0x11; 32]));
    for target in ["/v1/blocks/1".to_owned(), format!("/v1/accounts/{account}")] {
        let (status, body) = call(&api, &target, true);
        assert_eq!(status, 502, "{target}");
        assert_eq!(error_code(&body), json!("upstream_unavailable"));
    }
    let (status, _) = call(&api, "/v1/blocks/1/header", true);
    assert_eq!(status, 200);
    let (status, _) = call(&api, "/v1/light/head", true);
    assert_eq!(status, 200);
}

#[test]
fn a_dead_full_node_is_skipped_for_the_next_one() {
    let (live, node) = fake_node(vec![http("200 OK", "application/json", br#"{"ok":1}"#)]);
    let (mut api, _) = api_with("fallback", 2, 8);
    api.upstream = Upstream::new(&[dead_node(), live]);
    let (status, body) = call(&api, "/v1/blocks/1", true);
    assert_eq!((status, json_of(&body)), (200, json!({"ok": 1})));
    node.join().unwrap();
}

#[test]
fn a_pending_proof_request_is_a_pending_proof_job() {
    let tx = request();
    let txid = text(&SignedTxView::from(&tx).txid);
    let (url, node) = fake_node(vec![http(
        "200 OK",
        "application/json",
        &tx_view(&tx, None),
    )]);
    let (api, _) = api_asking("jobpending", 2, &url);
    let (status, body) = call(&api, &format!("/v1/light/proof-jobs/{txid}"), true);
    assert_eq!(status, 200);
    assert_eq!(json_of(&body), json!({"txid": txid, "status": "pending"}));
    let requests = node.join().unwrap();
    assert!(requests[0].starts_with(&format!("GET /v1/txs/{txid} HTTP/1.0")));
}

#[test]
fn an_included_proof_request_names_its_proof_and_the_block_of_the_light_nodes_own_headers() {
    let txid = text(&SignedTxView::from(&request()).txid);
    let leaves = leaves();
    let headers = rooted_chain(5, 3, root_of(&leaves));
    let proof = http("200 OK", "application/json", &inclusion_json(3, &leaves, 1));
    let (status, job) = job_with("jobincluded", &headers, 3, proof);
    assert_eq!(status, 200);
    assert_eq!(
        job,
        json!({
            "txid": txid,
            "status": "included",
            "proof_hash": text(&ProofHash(Hash32([5; 32]))),
            "height": 3,
            "block": text(&block_id(&headers[3])),
        })
    );
}

#[test]
fn a_proof_job_in_a_block_the_light_node_does_not_hold_is_unknown_block() {
    let tx = request();
    let txid = text(&SignedTxView::from(&tx).txid);
    let (url, node) = fake_node(vec![http(
        "200 OK",
        "application/json",
        &tx_view(&tx, Some(40)),
    )]);
    let (api, _) = api_asking("jobahead", 5, &url);
    let (status, body) = call(&api, &format!("/v1/light/proof-jobs/{txid}"), true);
    assert_eq!((status, error_code(&body)), (404, json!("unknown_block")));
    node.join().unwrap();
}

#[test]
fn a_tx_that_is_not_a_proof_request_or_is_unknown_is_not_a_proof_job() {
    let tx = transfer();
    let txid = text(&SignedTxView::from(&tx).txid);
    let (url, node) = fake_node(vec![
        http("200 OK", "application/json", &tx_view(&tx, None)),
        http("404 Not Found", "application/json", b"{}"),
    ]);
    let (api, _) = api_asking("jobnot", 2, &url);
    for _ in 0..2 {
        let (status, body) = call(&api, &format!("/v1/light/proof-jobs/{txid}"), true);
        assert_eq!(status, 404);
        assert_eq!(error_code(&body), json!("unknown_proof_job"));
    }
    node.join().unwrap();
}

/// The leaves of a block of three entries. The second is the proof hash of the tx views
/// of `tx_view`.
fn leaves() -> Vec<Hash32> {
    vec![Hash32([1; 32]), Hash32([5; 32]), Hash32([3; 32])]
}

/// The `tx_root` of a block with these leaves.
fn root_of(leaves: &[Hash32]) -> Hash32 {
    bound_root(leaf_count_u32(leaves.len()), &merkle_root(leaves))
}

/// A chain of `count` headers in which the one at height `at` has the `tx_root` `root`.
fn rooted_chain(count: u64, at: u64, root: Hash32) -> Vec<BlockHeader> {
    let mut headers = Vec::new();
    let mut parent = BlockId::ZERO;
    for height in 0..count {
        let mut next = header(height, parent);
        if height == at {
            next.tx_root = root;
        }
        parent = block_id(&next);
        headers.push(next);
    }
    headers
}

/// The JSON of `GET /v1/txs/{txid}/inclusion-proof` for leaf `index` of `leaves`.
fn inclusion_json(height: u64, leaves: &[Hash32], index: usize) -> Vec<u8> {
    let path = inclusion_proof(leaves, index).unwrap();
    serde_json::to_vec(&InclusionProof {
        height: Height(height),
        index: path.index,
        leaf_count: path.leaf_count,
        siblings: path.siblings,
    })
    .unwrap()
}

/// The status and the body of the proof job of `request()` for a light node holding
/// `headers`, when its full node says the tx is included at height `at` and then gives
/// `proof_answer` (a whole HTTP answer) as the inclusion proof.
fn job_with(name: &str, headers: &[BlockHeader], at: u64, proof_answer: Vec<u8>) -> (u16, Value) {
    let tx = request();
    let txid = text(&SignedTxView::from(&tx).txid);
    let (url, node) = fake_node(vec![
        http("200 OK", "application/json", &tx_view(&tx, Some(at))),
        proof_answer,
    ]);
    let mut store = HeaderStore::open(&path(name), 8).unwrap();
    for next in headers {
        store.push(*next).unwrap();
    }
    let api = LightApi::new(store, Upstream::new(&[url]));
    let (status, body) = call(&api, &format!("/v1/light/proof-jobs/{txid}"), true);
    node.join().unwrap();
    (status, json_of(&body))
}

#[test]
fn a_proof_job_is_not_included_when_the_proof_does_not_fit_the_local_header() {
    let leaves = leaves();
    let json = |body: &[u8]| http("200 OK", "application/json", body);
    let invalid = |(status, job): (u16, Value)| {
        assert_eq!(status, 502);
        assert_eq!(job["error"]["code"], json!("upstream_invalid"));
    };

    // the full node is on another chain: the block of the light node at height 3 has a
    // tx_root that does not commit to these leaves
    let divergent = rooted_chain(5, 3, Hash32([0xaa; 32]));
    invalid(job_with(
        "divergent",
        &divergent,
        3,
        json(&inclusion_json(3, &leaves, 1)),
    ));

    let headers = rooted_chain(5, 3, root_of(&leaves));
    // the path of another leaf
    invalid(job_with(
        "otherleaf",
        &headers,
        3,
        json(&inclusion_json(3, &leaves, 0)),
    ));
    // a path that is right but claims another height
    invalid(job_with(
        "otherheight",
        &headers,
        3,
        json(&inclusion_json(2, &leaves, 1)),
    ));
    // no inclusion proof, or one that does not parse
    invalid(job_with(
        "noproof",
        &headers,
        3,
        http("404 Not Found", "application/json", b"{}"),
    ));
    invalid(job_with("garbage", &headers, 3, json(b"not json")));
}
