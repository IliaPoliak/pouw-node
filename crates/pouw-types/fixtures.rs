//! The 20-block example chain of `pouw-docs/contracts/fixtures`. The blocks are built
//! with the same code the node uses (ids, Merkle root, eta, mask, signatures), so the
//! JSON files cannot drift from the encoding.
//!
//! `cargo test -p pouw-types fixtures` checks the chain. To rewrite the files:
//!
//! ```text
//! POUW_FIXTURES_DIR=/path/to/pouw-docs/contracts/fixtures \
//!     cargo test -p pouw-types write_fixtures -- --ignored
//! ```

#![allow(clippy::arithmetic_side_effects, clippy::too_many_lines)]

use std::{collections::BTreeMap, fs, path::PathBuf};

use pouw_crypto::{Address, FieldInput, Hash32, SigningKey, hash_to_field, sha256};
use serde_json::{Value, json};

use crate::{protocol::*, *};

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

fn miner(height: u64) -> Address {
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
pub fn chain() -> Vec<Block> {
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
            let eta = eta_chain(
                &block.header.parent,
                &block.compute_txs_root(),
                std::slice::from_ref(&proof_tx),
            )[0];
            let mask = mask(&block.header.miner, &circuit, usage);
            proof_tx.proof = mock_proof(&eta, &mask, &inputs);
            block.proof_txs.push(proof_tx);
        }
        blocks.push(seal(block));
    }
    blocks
}

/// The JSON view of the node API: the block plus its `hash`.
fn view(block: &Block) -> Value {
    let mut value = serde_json::to_value(block).unwrap();
    value["hash"] = serde_json::to_value(block_id(&block.header)).unwrap();
    value
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
        let bytes = borsh::to_vec(block).unwrap();
        assert_eq!(borsh::from_slice::<Block>(&bytes).unwrap(), *block);
    }
    assert!(blocks.iter().any(|block| !block.proof_txs.is_empty()));
}

#[test]
fn the_mock_proofs_verify_against_eta_and_mask() {
    let blocks = chain();
    for block in &blocks {
        for proof_tx in &block.proof_txs {
            let TxKind::ProofRequest {
                circuit,
                public_inputs,
                ..
            } = &proof_tx.request.body.kind
            else {
                panic!("a proof tx holds a proof request");
            };
            let eta = eta_chain(
                &block.header.parent,
                &block.compute_txs_root(),
                std::slice::from_ref(proof_tx),
            )[0];
            let mask = mask(&block.header.miner, circuit, proof_tx.usage_counter);
            assert_eq!(*proof_tx.proof, *mock_proof(&eta, &mask, public_inputs));
        }
    }
}

#[test]
#[ignore = "writes files, see the module docs"]
fn write_fixtures() {
    let dir = PathBuf::from(std::env::var("POUW_FIXTURES_DIR").expect("POUW_FIXTURES_DIR"));
    fs::create_dir_all(dir.join("blocks")).unwrap();
    let blocks = chain();
    let write = |path: PathBuf, value: &Value| {
        let mut text = serde_json::to_string_pretty(value).unwrap();
        text.push('\n');
        fs::write(path, text).unwrap();
    };
    for block in &blocks {
        let name = format!("blocks/block-{:02}.json", block.header.height.get());
        write(dir.join(name), &view(block));
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
            "seed": hex::encode([*seed; 32]),
            "address": serde_json::to_value(client(*seed).address()).unwrap(),
        })
    })
    .collect();
    write(
        dir.join("chain.json"),
        &json!({
            "chain_id": CHAIN.0,
            "blocks": blocks.iter().map(view).collect::<Vec<_>>(),
            "keys": keys,
        }),
    );
}
