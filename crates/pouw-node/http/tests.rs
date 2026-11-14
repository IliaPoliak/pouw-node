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
