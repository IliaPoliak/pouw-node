//! The 20-block example chain of `pouw-docs/contracts/fixtures`.
//!
//! The chain is a valid chain of a spec of its own (chain id 4242, an easy target,
//! alice and bob funded), written to `chainspec.json` next to the blocks. Every block
//! passes what a node checks: `check_pow`, `check_header`, `check_body`, the proof
//! verify of `MockProver` and `apply_block`. The files are the JSON views of
//! `node-api.md`, built with [`BlockView`] and [`ProofTxView`], so they have the shape
//! the node serves. The proofs are the mock backend's, the chain is a plain proof of
//! work chain.
//!
//! The files live in pouw-docs and CI does not read them, so a change of the encoding
//! does not fail them by itself. `TIP_ID` pins the id of the last block instead: a
//! change of the encoding or of a rule moves it, the test fails, and the files are
//! rewritten together with the constant.
//!
//! `cargo test -p pouw-node --test fixtures` checks the chain. To rewrite the files:
//!
//! ```text
//! POUW_FIXTURES_DIR=/path/to/pouw-docs/contracts/fixtures \
//!     cargo test -p pouw-node --test fixtures write_fixtures -- --ignored
//! ```

use std::{collections::BTreeMap, fmt::Write as _, fs, path::PathBuf};

use pouw_api::view::{BlockView, ProofTxView};
use pouw_consensus::{
    Anchor, HeaderContext, MemState, Scratch, apply_block, check_body, check_header, check_pow,
    median_time_past, next_target, state::apply,
};
use pouw_crypto::{Address, FieldInput, Hash32, SigningKey, hash_to_field};
use pouw_provers::{MockProver, Statement};
use pouw_types::{
    Account, Amount, Block, BlockHeader, ChainId, ChainSpec, CircuitId, ConstraintCount, Nonce,
    ProofSystem, ProofTx, SignedTx, SystemId, Target, Timestamp, TxBody, TxKind, U64, UsageCounter,
    block_id, check_genesis, eta_chain, genesis_id, mask, parse_chain_spec, sign_body,
};
use serde_json::{Value, json};

const CHAIN: ChainId = ChainId(4242);
const START: u64 = 1_793_600_000;
const BLOCKS: u64 = 20;
/// `target_block_secs` of the spec. The blocks are exactly on schedule, so the target
/// rule keeps the easy target and a block takes about 16 hashes.
const STEP: u64 = 10;
const FUNDS: u64 = 1_000_000;
const CIRCUIT: &[u8] = b"fixture circuit: x * y = z";

const ALICE: u8 = 1;
const BOB: u8 = 2;
const CAROL: u8 = 3;
const MINER_A: u8 = 0x0a;
const MINER_B: u8 = 0x0b;
/// The named keys of the fixtures, by seed.
const KEYS: [(&str, u8); 5] = [
    ("alice", ALICE),
    ("bob", BOB),
    ("carol", CAROL),
    ("miner-a", MINER_A),
    ("miner-b", MINER_B),
];

/// The id of the last block. Set it to what the test prints when a change of the chain
/// is intended, and rewrite the files.
const TIP_ID: &str = "blk:02a0a96c92e77c61eba286ea33f748d71bf8dbea317de052491a26dce496ee38";

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

fn miner(height: u64) -> Address {
    key(if height.is_multiple_of(2) {
        MINER_A
    } else {
        MINER_B
    })
    .address()
}

fn easy() -> Target {
    let mut bytes = [0xff; 32];
    bytes[0] = 0x0f;
    Target(bytes)
}

/// The spec of the fixture chain: its own chain id, `initial_target = pow_limit`, fee
/// coefficients of 1 and the balances of alice and bob.
fn spec() -> ChainSpec {
    let target = serde_json::to_value(easy()).unwrap();
    let address = |address: Address| serde_json::to_value(address).unwrap();
    let json = json!({
        "network": "fixtures",
        "params": {
            "chain_id": CHAIN.0,
            "initial_subsidy": 50,
            "halving_interval": 1000,
            "target_block_secs": STEP,
            "half_life_secs": 2880,
            "initial_target": target,
            "pow_limit": target,
            "max_future_secs": 300,
            "fee_per_public_input": 1,
            "fee_per_witness_kib": 1,
        },
        "genesis": {
            "timestamp": START,
            "miner": address(Address([0; 32])),
            "target": target,
            "nonce": 0,
        },
        "allocations": [
            { "address": address(key(ALICE).address()), "amount": FUNDS },
            { "address": address(key(BOB).address()), "amount": FUNDS },
        ],
        "min_chain_work": "0".repeat(64),
        "expected_genesis_id": format!("blk:{}", "0".repeat(64)),
    });
    let mut spec = parse_chain_spec(&json.to_string()).unwrap();
    spec.expected_genesis_id = genesis_id(&spec);
    spec
}

fn tx(signer: &SigningKey, nonce: u64, fee: u64, kind: TxKind) -> SignedTx {
    sign_body(
        &TxBody {
            chain_id: CHAIN,
            sender: signer.address(),
            nonce: Nonce(nonce),
            fee: Amount(fee),
            kind,
        },
        signer,
    )
}

/// Sets the Merkle root of `block` and searches the nonce that meets its target.
fn seal(mut block: Block) -> Block {
    block.header.tx_root = block.compute_tx_root();
    while block_id(&block.header).0.0 > block.header.target.0 {
        block.header.nonce = U64::new(block.header.nonce.get().wrapping_add(1));
    }
    block
}

/// The anchor of the target rule for the child of the last block of `blocks`.
fn anchor(spec: &ChainSpec, blocks: &[Block]) -> Anchor {
    match blocks {
        [genesis] => Anchor::first_block(&spec.params, &genesis.header),
        [genesis, first, ..] => Anchor::from_block(&first.header, &genesis.header),
        [] => panic!("a chain has its genesis"),
    }
}

/// `eta` and `mask` of the proof tx of `block`, the first two public inputs.
fn derived(block: &Block, proof_tx: &ProofTx) -> (Hash32, Hash32) {
    let TxKind::ProofRequest { circuit, .. } = &proof_tx.request.body.kind else {
        panic!("a proof tx holds a proof request");
    };
    let etas = eta_chain(
        &block.header.parent,
        &block.compute_txs_root(),
        std::slice::from_ref(proof_tx),
    );
    (
        etas[0],
        mask(&block.header.miner, circuit, proof_tx.usage_counter),
    )
}

/// The generated chain: its spec and the blocks, genesis first.
struct Chain {
    spec: ChainSpec,
    blocks: Vec<Block>,
}

/// Genesis plus 19 blocks: a circuit registered in block 1, a transfer in most blocks
/// and a proof request, proved with the mock backend, in every third block. Block `h`
/// is stamped `genesis + 10 * h`.
fn chain() -> Chain {
    let spec = spec();
    let prover = MockProver::default();
    let keys = prover.setup(CIRCUIT).unwrap();
    let complexity = prover.complexity(CIRCUIT).unwrap().0;
    let (alice, bob) = (key(ALICE), key(BOB));
    let register = tx(
        &alice,
        0,
        10,
        TxKind::RegisterCircuit {
            system: ProofSystem::Groth16,
            constraint_count: ConstraintCount(complexity),
            verifying_key: keys.verifying_key.clone(),
            circuit: Box::from(CIRCUIT),
        },
    );
    let circuit = CircuitId(pouw_types::txid(&register));
    let mut register = Some(register);
    let mut blocks = vec![check_genesis(&spec).unwrap()];
    let (mut alice_nonce, mut bob_nonce) = (1_u64, 0_u64);
    let mut counters: BTreeMap<(Address, CircuitId), UsageCounter> = BTreeMap::new();
    for height in 1..BLOCKS {
        let mut txs: Vec<SignedTx> = register.take().into_iter().collect();
        if !height.is_multiple_of(5) {
            let kind = TxKind::Transfer {
                to: key(CAROL).address(),
                amount: Amount(height.saturating_add(100)),
            };
            txs.push(tx(&bob, bob_nonce, 2, kind));
            bob_nonce = bob_nonce.saturating_add(1);
        }
        let parent = blocks.last().unwrap().header;
        let target =
            next_target(&spec.params, SystemId(0), &anchor(&spec, &blocks), &parent).unwrap();
        let mut block = Block {
            header: BlockHeader {
                height: U64::new(height),
                parent: block_id(&parent),
                timestamp: U64::new(START.saturating_add(STEP.saturating_mul(height))),
                miner: miner(height),
                target,
                nonce: U64::new(0),
                ..parent
            },
            txs,
            proof_txs: Vec::new(),
        };
        if height.is_multiple_of(3) {
            let inputs = vec![FieldInput([u8::try_from(height).unwrap(); 31])];
            let witness = [1, 2, 3, u8::try_from(height).unwrap()];
            let kind = TxKind::ProofRequest {
                circuit,
                public_inputs: inputs.clone(),
                witness: Box::from(witness),
            };
            let request = tx(&alice, alice_nonce, 5, kind);
            alice_nonce = alice_nonce.saturating_add(1);
            let counter = counters
                .get(&(block.header.miner, circuit))
                .map_or(UsageCounter(0), |last| last.checked_next().unwrap());
            counters.insert((block.header.miner, circuit), counter);
            let mut proof_tx = ProofTx {
                request,
                usage_counter: counter,
                proof: Box::from([]),
            };
            let (eta, mask) = derived(&block, &proof_tx);
            let statement = Statement::new(&eta, &mask, &inputs);
            proof_tx.proof = prover
                .prove(&keys.proving_key, &statement, &witness)
                .unwrap();
            block.proof_txs.push(proof_tx);
        }
        blocks.push(seal(block));
    }
    Chain { spec, blocks }
}

/// The state after genesis: the balances of the spec.
fn genesis_state(spec: &ChainSpec) -> MemState {
    let mut state = MemState::default();
    for allocation in &spec.allocations {
        let account = Account {
            balance: allocation.amount,
            nonce: Nonce(0),
        };
        state.accounts.insert(allocation.address, account);
    }
    state
}

/// Runs the checks of a node over every block after genesis, in order.
fn check(chain: &Chain) {
    let prover = MockProver::default();
    let params = &chain.spec.params;
    assert_eq!(chain.blocks[0], check_genesis(&chain.spec).unwrap());
    let mut state = genesis_state(&chain.spec);
    let mut verifying_keys: BTreeMap<CircuitId, Box<[u8]>> = BTreeMap::new();
    for (index, block) in chain.blocks.iter().enumerate().skip(1) {
        let before = &chain.blocks[..index];
        let parent = before.last().unwrap();
        assert_eq!(block.header.height.get(), u64::try_from(index).unwrap());
        check_pow(params, &block.header).unwrap();
        let timestamps: Vec<Timestamp> = before
            .iter()
            .map(|earlier| Timestamp(earlier.header.timestamp.get()))
            .collect();
        let anchor = anchor(&chain.spec, before);
        let context = HeaderContext {
            params,
            anchor: &anchor,
            mtp: median_time_past(&timestamps),
            now: Timestamp(block.header.timestamp.get()),
        };
        check_header(&context, &parent.header, &block.header).unwrap();
        let mut txids = Vec::new();
        block.txids_into(&mut txids);
        check_body(block, CHAIN, &txids, &mut Scratch::default()).unwrap();
        for (signed, id) in block.txs.iter().zip(&txids) {
            if let TxKind::RegisterCircuit { verifying_key, .. } = &signed.body.kind {
                verifying_keys.insert(CircuitId(*id), verifying_key.clone());
            }
        }
        let etas = eta_chain(
            &block_id(&parent.header),
            &block.compute_txs_root(),
            &block.proof_txs,
        );
        for (proof_tx, eta) in block.proof_txs.iter().zip(&etas) {
            let TxKind::ProofRequest {
                circuit,
                public_inputs,
                ..
            } = &proof_tx.request.body.kind
            else {
                panic!("a proof tx holds a proof request");
            };
            let mask = mask(&block.header.miner, circuit, proof_tx.usage_counter);
            let statement = Statement::new(eta, &mask, public_inputs);
            let verifying_key = &verifying_keys[circuit];
            assert!(
                prover
                    .verify(verifying_key, &statement, &proof_tx.proof)
                    .unwrap(),
                "the proof of block {index} verifies"
            );
        }
        let diff = apply_block(params, &state, block, &txids).unwrap();
        apply(&mut state, &diff).unwrap();
    }
}

/// The API view of `block`: ids, txids and the derived fields of its proof txs.
fn view(block: &Block) -> BlockView {
    let proofs = block
        .proof_txs
        .iter()
        .map(|proof_tx| {
            let (eta, mask) = derived(block, proof_tx);
            ProofTxView::new(
                proof_tx,
                hash_to_field(&eta),
                hash_to_field(&mask),
                MockProver::default().id(),
            )
        })
        .collect();
    BlockView::new(block, proofs)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        write!(out, "{byte:02x}").unwrap();
        out
    })
}

#[test]
fn the_chain_is_valid_and_every_block_passes_the_checks_of_a_node() {
    let chain = chain();
    assert_eq!(chain.blocks.len(), usize::try_from(BLOCKS).unwrap());
    check(&chain);
    assert!(chain.blocks.iter().any(|block| !block.proof_txs.is_empty()));
}

#[test]
fn the_chain_is_deterministic_and_its_tip_is_pinned() {
    let (first, second) = (chain(), chain());
    assert_eq!(first.blocks, second.blocks);
    assert_eq!(first.spec, second.spec);
    let tip = block_id(&first.blocks.last().unwrap().header);
    assert_eq!(
        tip.to_string(),
        TIP_ID,
        "the chain changed, copy the tip id above into TIP_ID and rewrite the files"
    );
}

#[test]
fn a_proof_of_another_statement_does_not_verify() {
    let chain = chain();
    let prover = MockProver::default();
    let block = chain
        .blocks
        .iter()
        .find(|block| !block.proof_txs.is_empty())
        .unwrap();
    let proof_tx = &block.proof_txs[0];
    let TxKind::ProofRequest { public_inputs, .. } = &proof_tx.request.body.kind else {
        panic!("a proof tx holds a proof request");
    };
    let (eta, mask) = derived(block, proof_tx);
    let key = prover.setup(CIRCUIT).unwrap().verifying_key;
    let right = Statement::new(&eta, &mask, public_inputs);
    assert!(prover.verify(&key, &right, &proof_tx.proof).unwrap());
    let other = [FieldInput([0xee; 31])];
    let wrong = Statement::new(&eta, &mask, &other);
    assert!(!prover.verify(&key, &wrong, &proof_tx.proof).unwrap());
}

#[test]
fn the_views_carry_the_derived_fields() {
    let chain = chain();
    let json = serde_json::to_value(view(&chain.blocks[3])).unwrap();
    assert_eq!(
        json["id"],
        serde_json::to_value(block_id(&chain.blocks[3].header)).unwrap()
    );
    let proof = &json["proof_txs"][0];
    for field in ["proof_hash", "request_txid", "eta", "mask", "proof_system"] {
        assert!(proof.get(field).is_some(), "{field}");
    }
    assert!(json["txs"][0].get("txid").is_some());
}

#[test]
#[ignore = "writes files, see the module docs"]
fn write_fixtures() {
    let dir = PathBuf::from(std::env::var("POUW_FIXTURES_DIR").expect("POUW_FIXTURES_DIR"));
    let blocks_dir = dir.join("blocks");
    if blocks_dir.exists() {
        fs::remove_dir_all(&blocks_dir).unwrap();
    }
    fs::create_dir_all(&blocks_dir).unwrap();
    let chain = chain();
    let views: Vec<Value> = chain
        .blocks
        .iter()
        .map(|block| serde_json::to_value(view(block)).unwrap())
        .collect();
    let write = |path: PathBuf, value: &Value| {
        let mut text = serde_json::to_string_pretty(value).unwrap();
        text.push('\n');
        fs::write(path, text).unwrap();
    };
    for (height, view) in views.iter().enumerate() {
        write(blocks_dir.join(format!("block-{height:02}.json")), view);
    }
    let keys: Vec<Value> = KEYS
        .iter()
        .map(|(name, seed)| {
            json!({
                "name": name,
                "seed": hex(&[*seed; 32]),
                "address": serde_json::to_value(key(*seed).address()).unwrap(),
            })
        })
        .collect();
    write(
        dir.join("chain.json"),
        &json!({ "chain_id": CHAIN.0, "blocks": views, "keys": keys }),
    );
    write(
        dir.join("chainspec.json"),
        &serde_json::to_value(&chain.spec).unwrap(),
    );
}
