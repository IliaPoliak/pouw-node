//! The 20-block example chain of `pouw-docs/contracts/fixtures`, in the JSON views of
//! `node-api.md` (`id`, `txid`, `proof_hash`, derived `eta`, `mask`, `proof_system`). The
//! blocks are built with the node code (ids, Merkle root, eta, mask, signatures), so the
//! files cannot drift from the encoding, and written through [`BlockView`], so they
//! cannot drift from the API.
//!
//! `cargo test -p pouw-api fixtures` checks the chain. To rewrite the files:
//!
//! ```text
//! POUW_FIXTURES_DIR=/path/to/pouw-docs/contracts/fixtures \
//!     cargo test -p pouw-api write_fixtures -- --ignored
//! ```

#![allow(clippy::arithmetic_side_effects, clippy::too_many_lines)]

use std::{collections::BTreeMap, fmt::Write as _, fs, path::PathBuf};

use pouw_crypto::{FieldInput, Hash32, SigningKey, hash_to_field, sha256};
use pouw_types::{
    Amount, Block, BlockHeader, BlockId, ChainId, CircuitId, ConstraintCount, Nonce, ProofSystem,
    ProofTx, SignedTx, Target, TxBody, TxKind, U32, U64, UsageCounter, block_id, eta_chain, mask,
    protocol::BLOCK_VERSION, sign_body, txid, verify_proof_tx, verify_tx,
};
use serde_json::{Value, json};

use crate::view::{BlockView, ProofTxView};

const CHAIN: ChainId = ChainId(1);
const START: u64 = 1_793_600_000;
const BLOCKS: u64 = 20;
const DOMAIN_MOCK_PROOF: &[u8] = b"pouw-zk/mock-proof/v1";
const CIRCUIT: &[u8] = b"fixture circuit: x * y = z";

fn easy() -> Target {
    let mut bytes = [0xff; 32];
    bytes[0] = 0x0f;
    Target(bytes)
}

fn client(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

fn miner(height: u64) -> pouw_crypto::Address {
    client(if height.is_multiple_of(2) { 0x0a } else { 0x0b }).address()
}

fn tx(key: &SigningKey, nonce: u64, fee: u64, kind: TxKind) -> SignedTx {
    sign_body(
        &TxBody {
            chain_id: CHAIN,
            sender: key.address(),
            nonce: Nonce(nonce),
            fee: Amount(fee),
            kind,
        },
        key,
    )
}

fn seal(mut block: Block) -> Block {
    block.header.tx_root = block.compute_tx_root();
    while block_id(&block.header).0.0 > block.header.target.0 {
        block.header.nonce = U64::new(block.header.nonce.get().wrapping_add(1));
    }
    block
}

/// The proof the mock backend makes: `sha256(domain || key || public inputs)`, with
/// `key = sha256(circuit)`.
fn mock_proof(eta: &Hash32, mask: &Hash32, inputs: &[FieldInput]) -> Box<[u8]> {
    let key = sha256(&[CIRCUIT]);
    let (eta, mask) = (hash_to_field(eta), hash_to_field(mask));
    let mut parts: Vec<&[u8]> = vec![DOMAIN_MOCK_PROOF, &key.0, &eta.0, &mask.0];
    parts.extend(inputs.iter().map(|input| input.0.as_slice()));
    Box::from(sha256(&parts).0)
}

/// Genesis plus 19 blocks: a circuit registered in block 1, a transfer in most blocks
/// and a proof request, proved with the mock backend, in every third block.
fn chain() -> Vec<Block> {
    let (alice, bob) = (client(1), client(2));
    let mut blocks = vec![seal(Block {
        header: BlockHeader {
            version: U32::new(BLOCK_VERSION),
            chain_id: U32::new(CHAIN.0),
            system_id: U64::new(0),
            height: U64::new(0),
            parent: BlockId::ZERO,
            timestamp: U64::new(START),
            miner: miner(0),
            tx_root: Hash32::ZERO,
            target: easy(),
            nonce: U64::new(0),
        },
        txs: Vec::new(),
        proof_txs: Vec::new(),
    })];
    let (mut alice_nonce, mut bob_nonce) = (0, 0);
    let mut circuit = None;
    let mut counters: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for height in 1..BLOCKS {
        let mut txs = Vec::new();
        if height == 1 {
            let register = tx(
                &alice,
                alice_nonce,
                10,
                TxKind::RegisterCircuit {
                    system: ProofSystem::Groth16,
                    constraint_count: ConstraintCount(u64::try_from(CIRCUIT.len()).unwrap()),
                    verifying_key: Box::from(sha256(&[CIRCUIT]).0),
                    circuit: Box::from(CIRCUIT),
                },
            );
            alice_nonce += 1;
            circuit = Some(CircuitId(txid(&register)));
            txs.push(register);
        }
        if !height.is_multiple_of(5) {
            txs.push(tx(
                &bob,
                bob_nonce,
                2,
                TxKind::Transfer {
                    to: client(3).address(),
                    amount: Amount(100 + height),
                },
            ));
            bob_nonce += 1;
        }
        let parent = blocks.last().unwrap().header;
        let mut block = Block {
            header: BlockHeader {
                height: U64::new(height),
                parent: block_id(&parent),
                timestamp: U64::new(START + 10 * height),
                miner: miner(height),
                nonce: U64::new(0),
                ..parent
            },
            txs,
            proof_txs: Vec::new(),
        };
        if let (true, Some(circuit)) = (height.is_multiple_of(3), circuit) {
            let inputs = vec![FieldInput([u8::try_from(height).unwrap(); 31])];
            let request = tx(
                &alice,
                alice_nonce,
                5,
                TxKind::ProofRequest {
                    circuit,
                    public_inputs: inputs.clone(),
                    witness: Box::from([1, 2, 3, u8::try_from(height).unwrap()]),
                },
            );
            alice_nonce += 1;
            let counter = counters.entry(block.header.miner.0).or_insert(0);
            let usage = UsageCounter(*counter);
            *counter += 1;
            let mut proof_tx = ProofTx {
                request,
                usage_counter: usage,
                proof: Box::from([0u8; 32]),
            };
            let (eta, mask) = derived(&block, &proof_tx);
            proof_tx.proof = mock_proof(&eta, &mask, &inputs);
            block.proof_txs.push(proof_tx);
        }
        blocks.push(seal(block));
    }
    blocks
}

/// `eta` and `mask` of the only proof tx of `block`, the first two public inputs.
fn derived(block: &Block, proof_tx: &ProofTx) -> (Hash32, Hash32) {
    let TxKind::ProofRequest { circuit, .. } = &proof_tx.request.body.kind else {
        panic!("a proof tx holds a proof request");
    };
    let eta = eta_chain(
        &block.header.parent,
        &block.compute_txs_root(),
        std::slice::from_ref(proof_tx),
    )[0];
    (
        eta,
        mask(&block.header.miner, circuit, proof_tx.usage_counter),
    )
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
                ProofSystem::Groth16,
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
fn the_chain_is_linked_and_every_commitment_matches() {
    let blocks = chain();
    assert_eq!(blocks.len(), 20);
    assert_eq!(blocks, chain(), "the chain is deterministic");
    for (index, block) in blocks.iter().enumerate() {
        assert_eq!(block.header.height.get(), u64::try_from(index).unwrap());
        assert_eq!(block.header.tx_root, block.compute_tx_root());
        assert!(block_id(&block.header).0.0 <= block.header.target.0);
        if index > 0 {
            assert_eq!(block.header.parent, block_id(&blocks[index - 1].header));
        }
        for signed in &block.txs {
            assert_eq!(verify_tx(signed), Ok(()));
        }
        for proof_tx in &block.proof_txs {
            assert_eq!(verify_proof_tx(proof_tx), Ok(()));
        }
    }
    assert!(blocks.iter().any(|block| !block.proof_txs.is_empty()));
}

#[test]
fn the_mock_proofs_match_eta_and_mask() {
    for block in &chain() {
        for proof_tx in &block.proof_txs {
            let TxKind::ProofRequest { public_inputs, .. } = &proof_tx.request.body.kind else {
                panic!("a proof tx holds a proof request");
            };
            let (eta, mask) = derived(block, proof_tx);
            assert_eq!(*proof_tx.proof, *mock_proof(&eta, &mask, public_inputs));
        }
    }
}

#[test]
fn the_views_carry_the_derived_fields() {
    let blocks = chain();
    let json = serde_json::to_value(view(&blocks[3])).unwrap();
    assert_eq!(
        json["id"],
        serde_json::to_value(block_id(&blocks[3].header)).unwrap()
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
    fs::create_dir_all(dir.join("blocks")).unwrap();
    let views: Vec<Value> = chain()
        .iter()
        .map(|block| serde_json::to_value(view(block)).unwrap())
        .collect();
    let write = |path: PathBuf, value: &Value| {
        let mut text = serde_json::to_string_pretty(value).unwrap();
        text.push('\n');
        fs::write(path, text).unwrap();
    };
    for (height, view) in views.iter().enumerate() {
        write(dir.join(format!("blocks/block-{height:02}.json")), view);
    }
    let keys: Vec<Value> = [
        (1u8, "alice"),
        (2, "bob"),
        (3, "carol"),
        (0x0a, "miner-a"),
        (0x0b, "miner-b"),
    ]
    .iter()
    .map(|(seed, name)| {
        json!({
            "name": name,
            "seed": hex(&[*seed; 32]),
            "address": serde_json::to_value(client(*seed).address()).unwrap(),
        })
    })
    .collect();
    write(
        dir.join("chain.json"),
        &json!({ "chain_id": CHAIN.0, "blocks": views, "keys": keys }),
    );
}
