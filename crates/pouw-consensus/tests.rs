use pouw_crypto::{Address, FieldInput, Hash32, SigningKey};
use pouw_types::{
    Amount, Block, BlockHeader, BlockId, ChainId, CircuitId, ConstraintCount, Nonce, ProofSystem,
    ProofTx, SignedTx, SystemId, Target, Timestamp, TxBody, TxId, TxKind, U32, U64, UsageCounter,
    block_id, protocol::MAX_CIRCUIT_BYTES, sign_body,
};

use crate::{
    Anchor, ConsensusParams, HeaderContext, InvalidBlock, InvalidTx, PowError, Scratch,
    TimestampError, check_body, check_header, check_pow, check_tx, next_target,
};

const CHAIN: ChainId = ChainId(7);

fn easy() -> Target {
    let mut bytes = [0xff; 32];
    bytes[0] = 0x0f;
    Target(bytes)
}

fn params() -> ConsensusParams {
    ConsensusParams {
        chain_id: CHAIN,
        initial_subsidy: Amount(50),
        halving_interval: 100,
        target_block_secs: 10,
        half_life_secs: 100,
        initial_target: easy(),
        pow_limit: easy(),
        max_future_secs: 300,
        fee_per_public_input: Amount(0),
        fee_per_witness_kib: Amount(0),
    }
}

fn anchor() -> Anchor {
    Anchor {
        height: pouw_types::Height(1),
        parent_timestamp: Timestamp(90),
        target: easy(),
    }
}

fn context<'a>(params: &'a ConsensusParams, anchor: &'a Anchor) -> HeaderContext<'a> {
    HeaderContext {
        params,
        anchor,
        mtp: Timestamp(100),
        now: Timestamp(110),
    }
}

fn mine(mut header: BlockHeader) -> BlockHeader {
    while block_id(&header).0.0 > header.target.0 {
        header.nonce = U64::new(header.nonce.get().wrapping_add(1));
    }
    header
}

fn key() -> SigningKey {
    SigningKey::from_seed([1; 32])
}

fn signed(nonce: u64, kind: TxKind) -> SignedTx {
    let key = key();
    sign_body(
        &TxBody {
            chain_id: CHAIN,
            sender: key.address(),
            nonce: Nonce(nonce),
            fee: Amount(1),
            kind,
        },
        &key,
    )
}

fn transfer(nonce: u64) -> SignedTx {
    signed(
        nonce,
        TxKind::Transfer {
            to: Address([2; 32]),
            amount: Amount(5),
        },
    )
}

fn request(nonce: u64) -> SignedTx {
    signed(
        nonce,
        TxKind::ProofRequest {
            circuit: CircuitId(TxId(Hash32([3; 32]))),
            public_inputs: vec![FieldInput([4; 31])],
            witness: Box::from([5]),
        },
    )
}

fn parent() -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(CHAIN.0),
        system_id: U64::new(0),
        height: U64::new(4),
        parent: BlockId::ZERO,
        timestamp: U64::new(100),
        miner: Address([9; 32]),
        tx_root: Hash32::ZERO,
        target: easy(),
        nonce: U64::new(0),
    }
}

fn seal(mut block: Block) -> Block {
    block.header.tx_root = block.compute_tx_root();
    block.header.target = expected_target(&block.header);
    block.header = mine(block.header);
    block
}

fn expected_target(header: &BlockHeader) -> Target {
    next_target(
        &params(),
        SystemId(header.system_id.get()),
        &anchor(),
        &parent(),
    )
    .unwrap()
}

fn check(header: &BlockHeader) -> Result<(), InvalidBlock> {
    let (params, anchor) = (params(), anchor());
    check_header(&context(&params, &anchor), &parent(), header)
}

fn body(block: &Block, chain_id: ChainId) -> Result<(), InvalidBlock> {
    let mut txids = Vec::new();
    block.txids_into(&mut txids);
    check_body(block, chain_id, &txids, &mut Scratch::default())
}

fn child(txs: Vec<SignedTx>, requests: Vec<SignedTx>) -> Block {
    let parent = parent();
    seal(Block {
        header: BlockHeader {
            height: U64::new(5),
            parent: block_id(&parent),
            timestamp: U64::new(110),
            ..parent
        },
        txs,
        proof_txs: requests
            .into_iter()
            .map(|request| ProofTx {
                request,
                usage_counter: UsageCounter(0),
                proof: Box::from([0xaa; 32]),
            })
            .collect(),
    })
}

fn valid() -> Block {
    child(vec![transfer(0)], vec![request(1)])
}

#[test]
fn a_valid_block_passes() {
    let block = valid();
    assert_eq!(check(&block.header), Ok(()));
    assert_eq!(body(&block, CHAIN), Ok(()));
}

#[test]
fn header_rules() {
    let mut header = valid().header;
    header.version = U32::new(2);
    assert_eq!(check(&header), Err(InvalidBlock::BadVersion { found: 2 }));

    let mut header = valid().header;
    header.chain_id = U32::new(8);
    assert_eq!(
        check(&header),
        Err(InvalidBlock::BadChainId {
            expected: CHAIN,
            found: ChainId(8)
        })
    );

    let mut header = valid().header;
    header.height = U64::new(6);
    assert!(matches!(
        check(&header),
        Err(InvalidBlock::BadHeight { .. })
    ));

    let mut header = valid().header;
    header.parent = BlockId::ZERO;
    assert_eq!(check(&header), Err(InvalidBlock::BadParent));
}

#[test]
fn the_target_must_be_the_one_of_the_rule() {
    let mut header = valid().header;
    let expected = header.target;
    let mut other = expected;
    other.0[1] = 0x00;
    header.target = other;
    assert_eq!(
        check(&header),
        Err(InvalidBlock::BadTarget {
            expected,
            found: other
        })
    );
}

#[test]
fn an_unknown_system_is_rejected() {
    let mut header = valid().header;
    header.system_id = U64::new(u64::MAX);
    assert!(matches!(check(&header), Err(InvalidBlock::Difficulty(_))));
    assert_eq!(
        check(&header).unwrap_err().reason_code(),
        "unknown_proof_system"
    );
}

#[test]
fn the_timestamp_rules_run_before_the_work() {
    let mut header = valid().header;
    header.timestamp = U64::new(100);
    let error = check(&header).unwrap_err();
    assert_eq!(
        error,
        InvalidBlock::Timestamp(TimestampError::NotAboveMedian {
            mtp: Timestamp(100),
            found: Timestamp(100)
        })
    );
    assert_eq!(error.reason_code(), "timestamp_not_above_median");

    let mut header = valid().header;
    header.timestamp = U64::new(411);
    let error = check(&header).unwrap_err();
    assert!(matches!(
        error,
        InvalidBlock::Timestamp(TimestampError::TooFarAhead { .. })
    ));
    assert_eq!(error.reason_code(), "timestamp_too_far_ahead");
}

#[test]
fn a_header_over_its_target_fails_the_work_check() {
    let mut header = valid().header;
    while block_id(&header).0.0 <= header.target.0 {
        header.nonce = U64::new(header.nonce.get().wrapping_add(1));
    }
    assert_eq!(check(&header), Ok(()));
    let error = InvalidBlock::from(check_pow(&params(), &header).unwrap_err());
    assert!(matches!(
        error,
        InvalidBlock::Pow(PowError::AboveTarget { .. })
    ));
    assert_eq!(error.reason_code(), "insufficient_work");
}

#[test]
fn tx_root_must_match() {
    let mut block = valid();
    block.header.tx_root = Hash32([1; 32]);
    assert_eq!(body(&block, CHAIN), Err(InvalidBlock::BadTxRoot));
}

#[test]
fn a_proof_request_in_txs_is_rejected() {
    let block = child(vec![request(0)], vec![]);
    assert!(matches!(
        body(&block, CHAIN),
        Err(InvalidBlock::Tx {
            proof: false,
            index: 0,
            source: InvalidTx::WrongKind { .. },
        })
    ));
}

#[test]
fn a_transfer_as_a_proof_request_is_rejected() {
    let block = child(vec![], vec![transfer(0)]);
    assert!(matches!(
        body(&block, CHAIN),
        Err(InvalidBlock::Tx {
            proof: true,
            source: InvalidTx::WrongKind { .. },
            ..
        })
    ));
}

#[test]
fn a_tampered_signature_is_rejected() {
    let mut tx = transfer(0);
    tx.body.fee = Amount(2);
    let block = child(vec![tx], vec![]);
    let error = body(&block, CHAIN).unwrap_err();
    assert_eq!(error.reason_code(), "bad_signature");
}

#[test]
fn the_root_is_checked_before_signatures() {
    let mut tx = transfer(0);
    tx.body.fee = Amount(2);
    let mut block = child(vec![tx], vec![]);
    block.header.tx_root = Hash32([1; 32]);
    assert_eq!(body(&block, CHAIN), Err(InvalidBlock::BadTxRoot));
}

#[test]
fn a_foreign_chain_id_is_rejected() {
    assert!(matches!(
        check_tx(&transfer(0), ChainId(8)),
        Err(InvalidTx::BadChainId { .. })
    ));
    let error = body(&valid(), ChainId(8)).unwrap_err();
    assert_eq!(error.reason_code(), "bad_chain_id");
}

#[test]
fn too_many_entries_are_rejected() {
    let txs = vec![transfer(0); pouw_types::protocol::MAX_TXS_PER_BLOCK + 1];
    let block = child(txs, vec![]);
    assert!(matches!(
        body(&block, CHAIN),
        Err(InvalidBlock::OverLimit {
            what: "entries",
            ..
        })
    ));
}

#[test]
fn more_than_one_proof_is_rejected() {
    let block = child(vec![], vec![request(0), request(1)]);
    assert!(matches!(
        body(&block, CHAIN),
        Err(InvalidBlock::OverLimit {
            what: "proof txs",
            found: 2,
            limit: 1,
        })
    ));
}

#[test]
fn the_largest_circuit_fits_in_a_block() {
    let circuit = signed(
        0,
        TxKind::RegisterCircuit {
            system: ProofSystem::Groth16,
            constraint_count: ConstraintCount(1),
            verifying_key: Box::from([1]),
            circuit: vec![0; MAX_CIRCUIT_BYTES - 1].into_boxed_slice(),
        },
    );
    assert_eq!(body(&child(vec![circuit], vec![]), CHAIN), Ok(()));
}

#[test]
fn reason_codes_of_the_contract() {
    assert_eq!(InvalidBlock::BadTxRoot.reason_code(), "bad_tx_root");
    assert_eq!(InvalidBlock::BadParent.reason_code(), "bad_parent");
    assert_eq!(
        InvalidBlock::BadChainId {
            expected: CHAIN,
            found: ChainId(8)
        }
        .reason_code(),
        "bad_header_chain_id"
    );
    assert_eq!(
        InvalidBlock::BadTarget {
            expected: easy(),
            found: easy()
        }
        .reason_code(),
        "bad_target"
    );
    assert_eq!(
        InvalidBlock::Pow(PowError::TargetAboveLimit {
            limit: easy(),
            found: easy()
        })
        .reason_code(),
        "bad_target"
    );
    assert_eq!(
        InvalidBlock::InvalidProof { index: 0 }.reason_code(),
        "invalid_proof"
    );
    assert_eq!(
        InvalidTx::BadNonce {
            expected: Nonce(4),
            found: Nonce(3)
        }
        .to_string(),
        "expected nonce 4, got 3"
    );
}

fn circuit_tx(nonce: u64, bytes: usize) -> SignedTx {
    signed(
        nonce,
        TxKind::RegisterCircuit {
            system: ProofSystem::Groth16,
            constraint_count: ConstraintCount(1),
            verifying_key: Box::from([1]),
            circuit: vec![0; bytes].into_boxed_slice(),
        },
    )
}

#[test]
fn a_block_over_the_byte_limit_is_rejected() {
    let txs = vec![
        circuit_tx(0, MAX_CIRCUIT_BYTES - 1),
        circuit_tx(1, MAX_CIRCUIT_BYTES - 1),
    ];
    let error = body(&child(txs, vec![]), CHAIN).unwrap_err();
    assert!(matches!(
        error,
        InvalidBlock::OverLimit { what: "bytes", .. }
    ));
    assert_eq!(error.reason_code(), "over_limit");
}

#[test]
fn a_transaction_over_its_limit_is_rejected_in_a_block() {
    let block = child(vec![circuit_tx(0, MAX_CIRCUIT_BYTES + 1)], vec![]);
    let error = body(&block, CHAIN).unwrap_err();
    assert!(matches!(
        error,
        InvalidBlock::Tx {
            proof: false,
            index: 0,
            source: InvalidTx::OverLimit { .. },
        }
    ));
    assert_eq!(error.reason_code(), "over_limit");
}
