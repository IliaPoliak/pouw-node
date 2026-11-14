use axum::{
    body::to_bytes,
    http::{HeaderValue, StatusCode},
};
use pouw_crypto::{Hash32, SigningKey};
use pouw_types::{ChainId, Target, TxBody, U32, U64, block_id, sign_body};

use super::*;

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future)
}

fn view(height: u64) -> BlockView {
    let header = BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(1),
        system_id: U64::new(0),
        height: U64::new(height),
        parent: BlockId::ZERO,
        timestamp: U64::new(height),
        miner: Address([9; 32]),
        tx_root: Hash32::ZERO,
        target: Target([0xff; 32]),
        nonce: U64::new(0),
    };
    BlockView {
        id: block_id(&header),
        header,
        txs: Vec::new(),
        proof_txs: Vec::new(),
    }
}

fn app() -> App {
    App {
        chain: Some(Arc::new(Chain {
            chain_id: ChainId(1),
            blocks: vec![view(0), view(1)],
        })),
        api: mpsc::channel(1).0,
        pending: PendingTxs::default(),
    }
}

fn accept(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::ACCEPT, HeaderValue::from_static(value));
    headers
}

fn signed(nonce: u64) -> SignedTx {
    let key = SigningKey::from_seed([1; 32]);
    sign_body(
        &TxBody {
            chain_id: ChainId(1),
            sender: key.address(),
            nonce: Nonce(nonce),
            fee: Amount(1),
            kind: TxKind::Transfer {
                to: Address([2; 32]),
                amount: Amount(5),
            },
        },
        &key,
    )
}

fn body_of(response: Response) -> Vec<u8> {
    block_on(to_bytes(response.into_body(), usize::MAX))
        .unwrap()
        .to_vec()
}

fn submit(app: &App, tx: &SignedTx) -> Response {
    let body = Bytes::from(borsh::to_vec(tx).unwrap());
    block_on(submit_tx(State(app.clone()), HeaderMap::new(), body))
}

fn get_tx(app: &App, id: &TxId, headers: HeaderMap) -> Response {
    block_on(tx(State(app.clone()), UrlPath(id.to_string()), headers))
}

#[test]
fn accept_names_a_media_type_whatever_its_parameters_and_neighbours() {
    assert!(accepts(&accept("application/json"), "application/json"));
    assert!(accepts(
        &accept("text/html, application/json;q=0.9, */*;q=0.1"),
        "application/json"
    ));
    assert!(accepts(&accept("APPLICATION/JSON"), "application/json"));
    assert!(!accepts(&accept("*/*"), "application/json"));
    assert!(!accepts(&HeaderMap::new(), "application/json"));
    assert!(!accepts(&accept("application/jsonx"), "application/json"));
}

#[test]
fn the_head_is_borsh_by_default_and_the_view_when_json_is_asked_for() {
    let app = app();
    let response = block_on(head(State(app.clone()), HeaderMap::new()));
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
    let decoded: BlockHeader = borsh::from_slice(&body_of(response)).unwrap();
    assert_eq!(decoded, view(1).header);

    let response = block_on(head(State(app), accept("application/json")));
    let json: Value = serde_json::from_slice(&body_of(response)).unwrap();
    assert_eq!(json["id"], json!(view(1).id));
}

#[test]
fn a_block_is_borsh_by_default_and_the_view_when_json_is_asked_for() {
    let app = app();
    let response = block_on(block(
        State(app.clone()),
        UrlPath("1".to_owned()),
        HeaderMap::new(),
    ));
    let decoded: Block = borsh::from_slice(&body_of(response)).unwrap();
    assert_eq!(decoded, block_of(&view(1)));

    let response = block_on(block(
        State(app),
        UrlPath("1".to_owned()),
        accept("application/json"),
    ));
    let json: Value = serde_json::from_slice(&body_of(response)).unwrap();
    assert_eq!(json["header"]["height"], json!(1));
}

#[test]
fn a_block_list_is_json_unless_borsh_is_asked_for_and_then_length_prefixed() {
    let app = app();
    let range = || {
        Query(Range {
            from: Some(0),
            to: Some(1),
        })
    };
    let response = block_on(blocks(State(app.clone()), range(), HeaderMap::new()));
    let json: Value = serde_json::from_slice(&body_of(response)).unwrap();
    assert_eq!(json["blocks"].as_array().unwrap().len(), 2);

    let response = block_on(blocks(
        State(app),
        range(),
        accept("application/octet-stream"),
    ));
    let bytes = body_of(response);
    let mut rest = bytes.as_slice();
    let mut heights = Vec::new();
    while !rest.is_empty() {
        let (len, tail) = rest.split_at(4);
        let len = usize::try_from(u32::from_le_bytes(len.try_into().unwrap())).unwrap();
        let (block, tail) = tail.split_at(len);
        let decoded: Block = borsh::from_slice(block).unwrap();
        heights.push(decoded.header.height.get());
        rest = tail;
    }
    assert_eq!(heights, [0, 1]);
}

#[test]
fn a_submitted_transaction_is_pending_and_polling_it_does_not_answer_404() {
    let app = app();
    let tx = signed(0);
    let id = txid(&tx);
    assert_eq!(
        get_tx(&app, &id, accept("application/json")).status(),
        StatusCode::NOT_FOUND
    );

    let response = submit(&app, &tx);
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let answer: Value = serde_json::from_slice(&body_of(response)).unwrap();
    assert_eq!(answer["txid"], json!(id));

    let response = get_tx(&app, &id, accept("application/json"));
    assert_eq!(response.status(), StatusCode::OK);
    let view: Value = serde_json::from_slice(&body_of(response)).unwrap();
    assert_eq!(view["status"], json!("pending"));
    assert_eq!(view["txid"], json!(id));
    assert!(view.get("height").is_none());

    let response = get_tx(&app, &id, HeaderMap::new());
    let decoded: SignedTx = borsh::from_slice(&body_of(response)).unwrap();
    assert_eq!(decoded, tx);
}

#[test]
fn the_mempool_lists_the_submitted_transactions_once_each() {
    let app = app();
    let (first, second) = (signed(0), signed(1));
    submit(&app, &first);
    submit(&app, &second);
    submit(&app, &first);
    let view: MempoolView =
        serde_json::from_slice(&body_of(block_on(mempool(State(app))))).unwrap();
    assert_eq!(view.tx_count, 2);
    assert_eq!(view.proof_request_count, 0);
    assert_eq!(view.txids.len(), 2);
    assert!(view.txids.contains(&txid(&first)) && view.txids.contains(&txid(&second)));
}

#[test]
fn a_transaction_with_a_bad_signature_is_rejected_and_not_kept() {
    let app = app();
    let mut tx = signed(0);
    tx.body.fee = Amount(2);
    assert_eq!(submit(&app, &tx).status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(app.pending.lock().unwrap().is_empty());
}

#[test]
fn the_pending_set_is_bounded() {
    let app = app();
    {
        let mut pending = app.pending.lock().unwrap();
        let tx = signed(0);
        for index in 0..MAX_PENDING {
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_le_bytes());
            pending.insert(TxId(Hash32(bytes)), tx.clone());
        }
    }
    let response = submit(&app, &signed(7));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(app.pending.lock().unwrap().len(), MAX_PENDING);
}

// ---------------------------------------------------------------- node mode

/// An app with no fixtures whose node loop is a thread that hands every request to
/// `answer`. The thread ends when the app is dropped.
fn live(mut answer: impl FnMut(ApiRequest) + Send + 'static) -> App {
    let (api, mut inbox) = mpsc::channel(8);
    std::thread::spawn(move || {
        while let Some(request) = inbox.blocking_recv() {
            answer(request);
        }
    });
    App {
        chain: None,
        api,
        pending: PendingTxs::default(),
    }
}

fn info() -> NodeInfo {
    NodeInfo {
        chain_id: ChainId(1),
        version: "0.1.0".to_owned(),
        height: Height(3),
        peers: 2,
    }
}

fn json_of(response: Response) -> Value {
    serde_json::from_slice(&body_of(response)).unwrap()
}

#[test]
fn a_live_node_answers_its_info() {
    let app = live(|request| {
        let ApiRequest::Node { reply } = request else {
            panic!("unexpected request {request:?}");
        };
        reply.send(Ok(info())).unwrap();
    });
    let response = block_on(node_info(State(app)));
    assert_eq!(response.status(), StatusCode::OK);
    let json = json_of(response);
    assert_eq!((&json["height"], &json["peers"]), (&json!(3), &json!(2)));
}

#[test]
fn a_live_block_is_the_stored_bytes_or_the_view() {
    let app = live(|request| {
        let ApiRequest::CanonicalBlock(query) = request else {
            panic!("unexpected request {request:?}");
        };
        let BlockQuery { key, json, reply } = *query;
        assert_eq!(key, BlockKey::Height(Height(1)));
        let answer = if json {
            BlockReply::View(Box::new(view(1)))
        } else {
            BlockReply::Bytes(borsh::to_vec(&block_of(&view(1))).unwrap())
        };
        reply.send(Ok(Some(answer))).unwrap();
    });
    let call = |headers| block_on(block(State(app.clone()), UrlPath("1".to_owned()), headers));
    let decoded: Block = borsh::from_slice(&body_of(call(HeaderMap::new()))).unwrap();
    assert_eq!(decoded, block_of(&view(1)));
    let json = json_of(call(accept("application/json")));
    assert_eq!(json["header"]["height"], json!(1));
}

#[test]
fn a_live_block_that_is_not_there_or_not_a_key_is_404() {
    let app = live(|request| {
        let ApiRequest::CanonicalBlock(query) = request else {
            panic!("unexpected request {request:?}");
        };
        query.reply.send(Ok(None)).unwrap();
    });
    for key in ["9", "not-a-key"] {
        let response = block_on(block(
            State(app.clone()),
            UrlPath(key.to_owned()),
            HeaderMap::new(),
        ));
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

#[test]
fn live_ranges_report_a_cap_and_a_reversed_range() {
    for (ranged, status, code) in [
        (
            Ranged::TooLarge,
            StatusCode::UNPROCESSABLE_ENTITY,
            "range_too_large",
        ),
        (Ranged::FromAboveTo, StatusCode::BAD_REQUEST, "malformed"),
    ] {
        let app = live(move |request| {
            let ApiRequest::Headers { reply, .. } = request else {
                panic!("unexpected request {request:?}");
            };
            reply.send(Ok(ranged.clone())).unwrap();
        });
        let range = Query(Range {
            from: Some(5),
            to: Some(1),
        });
        let response = block_on(headers(State(app), range));
        assert_eq!(response.status(), status);
        assert_eq!(json_of(response)["error"]["code"], json!(code));
    }
}

#[test]
fn an_expired_event_cursor_is_410_with_the_oldest_seq() {
    let app = live(|request| {
        let ApiRequest::Events { reply, .. } = request else {
            panic!("unexpected request {request:?}");
        };
        reply.send(Err(CursorExpired { oldest_seq: 9 })).unwrap();
    });
    let query = Query(EventsQuery {
        after: Some(1),
        limit: None,
    });
    let response = block_on(events(State(app), query));
    assert_eq!(response.status(), StatusCode::GONE);
    let json = json_of(response);
    assert_eq!(json["error"]["code"], json!("cursor_expired"));
    assert_eq!(json["error"]["details"]["oldest_seq"], json!(9));
}

fn submit_live(outcome: TxOutcome) -> Response {
    let app = live(move |request| match request {
        ApiRequest::Node { reply } => reply.send(Ok(info())).unwrap(),
        ApiRequest::SubmitTx { checked, reply } => {
            assert!(checked.is_ok());
            reply.send(outcome.clone()).unwrap();
        }
        other => panic!("unexpected request {other:?}"),
    });
    let body = Bytes::from(borsh::to_vec(&signed(0)).unwrap());
    block_on(submit_tx(State(app), HeaderMap::new(), body))
}

#[test]
fn a_live_submission_is_answered_by_the_outcome_in_the_pool() {
    let id = txid(&signed(0));
    let pooled = submit_live(TxOutcome::Pooled(id));
    assert_eq!(pooled.status(), StatusCode::ACCEPTED);
    assert_eq!(json_of(pooled)["txid"], json!(id));

    let again = submit_live(TxOutcome::Refused(MempoolError::Duplicate(id)));
    assert_eq!(again.status(), StatusCode::ACCEPTED);

    let full = submit_live(TxOutcome::Refused(MempoolError::Full { max_bytes: 1 }));
    assert_eq!(full.status(), StatusCode::SERVICE_UNAVAILABLE);

    let cheap = submit_live(TxOutcome::Refused(MempoolError::Underpriced {
        existing: id,
        fee: Amount(1),
    }));
    assert_eq!(cheap.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_of(cheap)["error"]["code"], json!("underpriced"));
}

#[test]
fn a_live_submission_that_breaks_a_rule_carries_its_reason_code() {
    let invalid = pouw_consensus::InvalidTx::BadNonce {
        expected: Nonce(1),
        found: Nonce(0),
    };
    let response = submit_live(TxOutcome::Invalid(invalid));
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(json_of(response)["error"]["code"], json!("bad_nonce"));
}

#[test]
fn a_node_that_does_not_answer_is_busy() {
    let (api, _inbox) = mpsc::channel(1);
    let app = App {
        chain: None,
        api,
        pending: PendingTxs::default(),
    };
    // the queue holds one request and nobody reads it, so the next one is refused at once
    let (reply, _answer) = oneshot::channel();
    crate::api::submit(&app.api, ApiRequest::Mempool { reply }).unwrap();
    let response = block_on(mempool(State(app)));
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
