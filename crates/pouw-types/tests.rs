use pouw_crypto::{Address, FieldInput, Hash32, SigningKey, sha256};
use zerocopy::{FromBytes, IntoBytes};

use crate::{protocol::*, *};

const CHAIN: ChainId = ChainId(1);

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

fn body(key: &SigningKey, nonce: u64, kind: TxKind) -> TxBody {
    TxBody {
        chain_id: CHAIN,
        sender: key.address(),
        nonce: Nonce(nonce),
        fee: Amount(10),
        kind,
    }
}

fn register(key: &SigningKey) -> SignedTx {
    sign_body(
        &body(
            key,
            1,
            TxKind::RegisterCircuit {
                system: ProofSystem::PlonkKzg,
                constraint_count: ConstraintCount(1234),
                verifying_key: vec![1, 2, 3].into_boxed_slice(),
                circuit: vec![4, 5, 6, 7].into_boxed_slice(),
            },
        ),
        key,
    )
}

fn transfer(key: &SigningKey) -> SignedTx {
    sign_body(
        &body(
            key,
            0,
            TxKind::Transfer {
                to: Address([0x22; 32]),
                amount: Amount(1000),
            },
        ),
        key,
    )
}

fn proof_tx(key: &SigningKey, circuit: CircuitId, counter: u64) -> ProofTx {
    let request = sign_body(
        &body(
            key,
            2,
            TxKind::ProofRequest {
                circuit,
                public_inputs: vec![FieldInput([9; 31]), FieldInput([0; 31])],
                witness: vec![0xde, 0xad, 0xbe, 0xef].into_boxed_slice(),
            },
        ),
        key,
    );
    ProofTx {
        request,
        usage_counter: UsageCounter(counter),
        proof: vec![0xaa; 128].into_boxed_slice(),
    }
}

fn sample_block() -> Block {
    let k = key(5);
    let register_tx = register(&k);
    let circuit = CircuitId(txid(&register_tx));
    let txs = vec![transfer(&k), register_tx];
    let proof_txs = vec![proof_tx(&k, circuit, 0)];
    let ids: Vec<Hash32> = txs
        .iter()
        .map(|tx| txid(tx).hash())
        .chain(proof_txs.iter().map(|p| proof_tx_hash(p).hash()))
        .collect();
    Block {
        header: BlockHeader {
            version: U32::new(BLOCK_VERSION),
            chain_id: U32::new(CHAIN.0),
            system_id: U64::new(0),
            height: U64::new(7),
            parent: BlockId(Hash32([3; 32])),
            timestamp: U64::new(1_760_000_000),
            miner: k.address(),
            tx_root: bound_root(leaf_count_u32(ids.len()), &merkle_root(&ids)),
            target: Target([0xff; 32]),
            nonce: U64::new(99),
        },
        txs,
        proof_txs,
    }
}

#[test]
fn borsh_round_trip_of_a_block() {
    let block = sample_block();
    let bytes = borsh::to_vec(&block).unwrap();
    let back: Block = borsh::from_slice(&bytes).unwrap();
    assert_eq!(back, block);
}

#[test]
fn serde_json_round_trip_of_a_block() {
    let block = sample_block();
    let json = serde_json::to_string(&block).unwrap();
    let back: Block = serde_json::from_str(&json).unwrap();
    assert_eq!(back, block);
}

#[test]
fn json_conventions() {
    let block = sample_block();
    let id = txid(&block.txs[0]);
    assert!(serde_json::to_string(&id).unwrap().starts_with("\"tx:"));
    let value = serde_json::to_value(&block).unwrap();
    assert_eq!(value["txs"][0]["body"]["kind"], "transfer");
    assert_eq!(value["txs"][1]["body"]["kind"], "register_circuit");
    assert_eq!(value["txs"][1]["body"]["system"], "plonk_kzg");
    assert_eq!(
        value["proof_txs"][0]["request"]["body"]["kind"],
        "proof_request"
    );
    assert_eq!(value["txs"][0]["body"]["amount"], 1000);
    assert_eq!(value["txs"][1]["body"]["verifying_key"], "AQID");
    assert!(
        value["header"]["parent"]
            .as_str()
            .unwrap()
            .starts_with("blk:")
    );
    assert!(
        value["proof_txs"][0]["request"]["body"]["circuit"]
            .as_str()
            .unwrap()
            .starts_with("circ:")
    );
    let body = &value["txs"][0]["body"];
    assert!(body["kind"].is_string());
    assert!(body.get("to").is_some());
    let input = value["proof_txs"][0]["request"]["body"]["public_inputs"][0]
        .as_str()
        .unwrap();
    assert_eq!(input, "09".repeat(31));
}

#[test]
fn a_block_id_does_not_parse_as_a_txid() {
    let blk = format!("blk:{}", "00".repeat(32));
    assert!(blk.parse::<TxId>().is_err());
    assert!(serde_json::from_str::<TxId>(&format!("\"{blk}\"")).is_err());
    assert!(blk.parse::<BlockId>().is_ok());
    assert!(
        format!("tx:{}", "00".repeat(32))
            .parse::<CircuitId>()
            .is_err()
    );
}

#[test]
fn transfer_body_borsh_hex() {
    let body = TxBody {
        chain_id: ChainId(1),
        sender: Address([0x11; 32]),
        nonce: Nonce(0),
        fee: Amount(10),
        kind: TxKind::Transfer {
            to: Address([0x22; 32]),
            amount: Amount(1000),
        },
    };
    let expected = [
        "01000000".to_string(),
        "11".repeat(32),
        "0000000000000000".to_string(),
        "0a00000000000000".to_string(),
        "00".to_string(),
        "22".repeat(32),
        "e803000000000000".to_string(),
    ]
    .concat();
    let actual = hex::encode(borsh::to_vec(&body).unwrap());
    assert_eq!(actual, expected);
}

#[test]
fn sign_and_verify_each_kind() {
    let k = key(1);
    let block = sample_block();
    for tx in &block.txs {
        assert_eq!(verify_tx(tx), Ok(()));
    }
    assert_eq!(verify_proof_tx(&block.proof_txs[0]), Ok(()));
    assert_eq!(verify_tx(&transfer(&k)), Ok(()));
}

#[test]
fn tampered_tx_fails() {
    let k = key(1);
    let mut tx = transfer(&k);
    tx.body.fee = Amount(11);
    assert!(verify_tx(&tx).is_err());
}

#[test]
fn oversized_fields_are_rejected() {
    let k = key(1);
    let tx = sign_body(
        &body(
            &k,
            0,
            TxKind::ProofRequest {
                circuit: CircuitId(TxId(Hash32::ZERO)),
                public_inputs: vec![FieldInput([0; 31]); MAX_PUBLIC_INPUTS + 1],
                witness: vec![].into_boxed_slice(),
            },
        ),
        &k,
    );
    assert!(matches!(verify_tx(&tx), Err(TxError::OverLimit { .. })));
}

#[test]
fn txid_changes_with_the_signature() {
    let k = key(1);
    let a = transfer(&k);
    let mut b = a.clone();
    b.signature.0[0] ^= 1;
    assert_ne!(txid(&a), txid(&b));
    assert_eq!(txid(&a), TxId(sha256(&[&borsh::to_vec(&a).unwrap()])));
}

#[test]
fn eta_chain_follows_the_spec() {
    let k = key(1);
    let circuit = CircuitId(TxId(Hash32([8; 32])));
    let proofs = vec![
        proof_tx(&k, circuit, 0),
        proof_tx(&k, circuit, 1),
        proof_tx(&k, circuit, 2),
    ];
    let prev = BlockId(Hash32([4; 32]));
    let root = Hash32([5; 32]);
    let etas = eta_chain(&prev, &root, &proofs);
    assert_eq!(etas.len(), 3);
    let domain = b"pouw-zk/eta/v1";
    let eta0 = sha256(&[domain, &[4; 32], &[5; 32]]);
    let eta1 = sha256(&[domain, &eta0.0, &sha256(&[&proofs[0].proof]).0]);
    let eta2 = sha256(&[domain, &eta1.0, &sha256(&[&proofs[1].proof]).0]);
    assert_eq!(etas, vec![eta0, eta1, eta2]);
    assert_eq!(eta_chain(&prev, &root, &[]), Vec::new());
}

#[test]
fn mask_follows_the_spec() {
    let miner = Address([6; 32]);
    let circuit = CircuitId(TxId(Hash32([8; 32])));
    let expected = sha256(&[b"pouw-zk/mask/v1", &[6; 32], &[8; 32], &3u64.to_le_bytes()]);
    assert_eq!(mask(&miner, &circuit, UsageCounter(3)), expected);
    assert_ne!(mask(&miner, &circuit, UsageCounter(4)), expected);
}

#[test]
fn txid_test_vector() {
    let tx = transfer(&key(1));
    assert_eq!(
        txid(&tx).to_string(),
        "tx:41ef667fcdab0af9fbf57805b90f90a60825c43d4a796b1f26980207e622e6f7"
    );
}

#[test]
fn tx_body_json_is_flat() {
    let body = TxBody {
        chain_id: ChainId(1),
        sender: Address([0x11; 32]),
        nonce: Nonce(4),
        fee: Amount(120),
        kind: TxKind::Transfer {
            to: Address([0x22; 32]),
            amount: Amount(500),
        },
    };
    let json = serde_json::to_string(&body).unwrap();
    let expected = format!(
        r#"{{"chain_id":1,"sender":"addr:{}","nonce":4,"fee":120,"kind":"transfer","to":"addr:{}","amount":500}}"#,
        "11".repeat(32),
        "22".repeat(32)
    );
    assert_eq!(json, expected);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["kind"], "transfer");
    assert!(!value["kind"].is_object());
    assert_eq!(serde_json::from_str::<TxBody>(&json).unwrap(), body);
}

mod vectors {
    use pouw_crypto::{Hash32, SigningKey, hash_to_field, sha256};

    use crate::{protocol::DOMAIN_TX_SIG, *};

    fn transfer_tx() -> SignedTx {
        let key = SigningKey::from_seed([1; 32]);
        let body = TxBody {
            chain_id: ChainId(1),
            sender: key.address(),
            nonce: Nonce(0),
            fee: Amount(10),
            kind: TxKind::Transfer {
                to: pouw_crypto::Address([0x22; 32]),
                amount: Amount(1000),
            },
        };
        sign_body(&body, &key)
    }

    fn ids() -> Vec<Hash32> {
        (1..=4u8).map(|n| Hash32([n; 32])).collect()
    }

    #[test]
    fn transfer_pinned_from_implementation() {
        let tx = transfer_tx();
        assert_eq!(
            hex::encode(tx.body.sender.0),
            "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c"
        );
        let body = borsh::to_vec(&tx.body).unwrap();
        assert_eq!(body.len(), 93);
        assert_eq!(
            hex::encode(&body),
            "010000008a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c00000000000000000a00000000000000002222222222222222222222222222222222222222222222222222222222222222e803000000000000"
        );
        assert_eq!(signing_bytes(&tx.body), [DOMAIN_TX_SIG, &body].concat());
        assert_eq!(
            hex::encode(tx.signature.0),
            "507d5e19dca04f6961f00fd6f6cb0e31dffa042c43357bada9160696778aa4f45c720c67845a2251dfcd4e0fd078790dec9cd32392b651e1ecb24128960f5304"
        );
        assert_eq!(borsh::to_vec(&tx).unwrap().len(), 157);
        assert_eq!(
            hex::encode(txid(&tx).hash().0),
            "41ef667fcdab0af9fbf57805b90f90a60825c43d4a796b1f26980207e622e6f7"
        );
    }

    #[test]
    fn merkle_pinned_from_implementation() {
        let ids = ids();
        let expected = [
            "dcffe786ded16d283c663846ad0c4ff26558fccde36ca9d30b2ea19eade9fc0e",
            "3a066e0f40c6a1981ebfa60d2411625d0517ae22c2fc8c7c1784ff8a75c78565",
            "df896896c799531f1fd1e556cea26a6989ab06853bcbfdd3e4f5097a611f658f",
            "3b3c0ce45d11517a54300a196b61497c4165150d72b7782a4548e3984da771b2",
        ];
        for (n, root) in expected.iter().enumerate() {
            assert_eq!(merkle_root(&ids[..=n]).to_string(), *root);
        }
        assert_eq!(
            merkle_root(&[]).to_string(),
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
        );
        let bound = [
            "f2b2f05a836b7f4277d8cfd5cf46db32f029b4d30a7c991b2a434614a3066a50",
            "0c161ee6b7b605311d901a8092dafdd0c11596de35dac22c398fef177bcbc23e",
            "5719908c8bd98ae775ca5efeab6e6cd1afcd5727ce4712e33987bb42ad1f28fd",
            "1f1ab170a7a76d18a0540443863241e12af7229587fca33f331129ee433ff9a9",
            "fa110a0a7f0eb857f7418377ddd48f1ea27a192919bfe248ce550dc60d6a92d1",
        ];
        for (n, root) in bound.iter().enumerate() {
            let merkle = merkle_root(&ids[..n]);
            assert_eq!(bound_root(leaf_count_u32(n), &merkle).to_string(), *root);
        }
        let proof = |ids: &[Hash32], index| -> Vec<String> {
            inclusion_proof(ids, index)
                .unwrap()
                .siblings
                .iter()
                .map(ToString::to_string)
                .collect()
        };
        assert_eq!(
            proof(&ids, 2),
            [
                "1da033bf8927ed69376d91533748494f7f5e88c20603dede2afc9bfd43d46f17",
                "3a066e0f40c6a1981ebfa60d2411625d0517ae22c2fc8c7c1784ff8a75c78565"
            ]
        );
        assert_eq!(
            proof(&ids[..3], 2),
            ["3a066e0f40c6a1981ebfa60d2411625d0517ae22c2fc8c7c1784ff8a75c78565"]
        );
    }

    #[test]
    fn field_pinned_from_implementation() {
        assert_eq!(
            hash_to_field(&sha256(&[b"abc"])).to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015"
        );
    }
}

#[test]
fn block_roots_match_the_header() {
    let block = sample_block();
    assert_eq!(block.compute_tx_root(), block.header.tx_root);
    let txids: Vec<Hash32> = block.txs.iter().map(|tx| txid(tx).hash()).collect();
    assert_eq!(block.compute_txs_root(), merkle_root(&txids));
    assert_eq!(block.leaf_ids().len(), block.leaf_count());
}

#[test]
fn txids_list_the_txs_then_the_requests_each_once() {
    let block = sample_block();
    let mut ids = vec![TxId(Hash32([0; 32]))];
    block.txids_into(&mut ids);
    let expected: Vec<TxId> = block
        .txs
        .iter()
        .map(txid)
        .chain(block.proof_txs.iter().map(|p| txid(&p.request)))
        .collect();
    assert_eq!(ids, expected);
    assert_eq!(ids.len(), block.txs.len() + block.proof_txs.len());
}

#[test]
fn the_root_from_known_txids_is_the_computed_root() {
    let block = sample_block();
    let mut ids = Vec::new();
    block.txids_into(&mut ids);
    let mut leaves = vec![Hash32([0; 32]); 9];
    assert_eq!(block.tx_root_from(&ids, &mut leaves), block.header.tx_root);
    assert_eq!(leaves.len(), 1);
}

#[test]
fn fixed_size_newtypes_have_the_borsh_bytes() {
    fn same<T: IntoBytes + zerocopy::Immutable + borsh::BorshSerialize + std::fmt::Debug>(
        value: &T,
    ) {
        assert_eq!(value.as_bytes(), borsh::to_vec(value).unwrap(), "{value:?}");
    }
    same(&Hash32([0xab; 32]));
    same(&Address([0x11; 32]));
    same(&pouw_crypto::Signature([7; 64]));
    same(&FieldInput([9; 31]));
    same(&TxId(Hash32([1; 32])));
    same(&BlockId(Hash32([2; 32])));
    same(&CircuitId(TxId(Hash32([3; 32]))));
    same(&ProofHash(Hash32([4; 32])));
}

#[test]
fn header_bytes_are_the_borsh_bytes() {
    let header = sample_block().header;
    assert_eq!(header.as_bytes(), borsh::to_vec(&header).unwrap());
    let view = BlockHeader::ref_from_bytes(header.as_bytes()).unwrap();
    assert_eq!(view, &header);
    assert!(BlockHeader::ref_from_bytes(&header.as_bytes()[1..]).is_err());
}

#[test]
fn block_id_hashes_the_domain_and_the_header_bytes() {
    let header = sample_block().header;
    assert_eq!(
        block_id(&header),
        BlockId(sha256(&[DOMAIN_HEADER, &borsh::to_vec(&header).unwrap()]))
    );
    assert_ne!(block_id(&header).0, sha256(&[header.as_bytes()]));
}

#[test]
fn header_is_168_bytes_and_encoded_len_agrees() {
    let block = sample_block();
    assert_eq!(borsh::to_vec(&block.header).unwrap().len(), 168);
    assert_eq!(encoded_len(&block), borsh::to_vec(&block).unwrap().len());
}

/// The header of the golden vectors, written field by field with plain literals.
fn golden_header() -> BlockHeader {
    BlockHeader {
        version: U32::new(1),
        chain_id: U32::new(7),
        system_id: U64::new(0),
        height: U64::new(7),
        parent: BlockId(Hash32([3; 32])),
        timestamp: U64::new(1_760_000_000),
        miner: Address([2; 32]),
        tx_root: Hash32([9; 32]),
        target: Target({
            let mut bytes = [0; 32];
            bytes[2] = 0xff;
            bytes[3] = 0xff;
            bytes
        }),
        nonce: U64::new(0x0102_0304_0506_0708),
    }
}

/// Computed independently with `python3 -I`: the fields packed with `struct` as
/// `<I I Q Q 32s Q 32s 32s 32s Q` (target as the raw big-endian bytes).
const GOLDEN_HEADER_HEX: &str = "0100000007000000000000000000000007000000000000000303030303030303030303030303030303030303030303030303030303030303\
0078e768000000000202020202020202020202020202020202020202020202020202020202020202\
0909090909090909090909090909090909090909090909090909090909090909\
0000ffff00000000000000000000000000000000000000000000000000000000\
0807060504030201";

/// `hashlib.sha256(b"pouw-zk/header/v1" + header_bytes).hexdigest()` in `python3 -I`.
const GOLDEN_BLOCK_ID_HEX: &str =
    "68ffd9ba2b7d280b832924cd42704d5d7daf3b202e55f1c85d7e5742d2484ab0";

#[test]
fn golden_header_bytes() {
    let header = golden_header();
    assert_eq!(hex::encode(header.as_bytes()), GOLDEN_HEADER_HEX);
    assert_eq!(
        hex::encode(borsh::to_vec(&header).unwrap()),
        GOLDEN_HEADER_HEX
    );
    let bytes = hex::decode(GOLDEN_HEADER_HEX).unwrap();
    assert_eq!(BlockHeader::ref_from_versioned(&bytes).unwrap(), &header);
}

#[test]
fn golden_block_id() {
    let id = block_id(&golden_header());
    assert_eq!(id.to_string(), format!("blk:{GOLDEN_BLOCK_ID_HEX}"));
}

#[test]
fn every_header_field_changes_the_block_id() {
    let base = golden_header();
    let id = block_id(&base);
    let mut changed = Vec::new();
    for offset in [0, 4, 8, 16, 24, 56, 64, 96, 128, 160] {
        let mut bytes = base.as_bytes().to_vec();
        bytes[offset] ^= 1;
        changed.push(*BlockHeader::ref_from_bytes(&bytes).unwrap());
    }
    for header in changed {
        assert_ne!(block_id(&header), id);
    }
}

fn target_with_top_bits(top: &[u8]) -> Target {
    let mut bytes = [0u8; 32];
    bytes[..top.len()].copy_from_slice(top);
    Target(bytes)
}

fn all_ones_below(bits: usize) -> Target {
    let top = U256::ONE.checked_shl(bits).unwrap_or(U256::ZERO);
    Target::from_u256(top.wrapping_sub(U256::ONE))
}

/// Expected values are `2**256 // (t + 1)` computed with python3 integers.
#[test]
fn block_work_vectors() {
    let work = |target: Target| block_work(&target).0;
    assert_eq!(work(Target([0xff; 32])), U256::from(1u64));
    assert_eq!(work(all_ones_below(255)), U256::from(2u64));
    assert_eq!(work(target_with_top_bits(&[0x80])), U256::from(1u64));
    assert_eq!(work(all_ones_below(240)), U256::from(65_536u64));
    assert_eq!(
        work(target_with_top_bits(&[0, 0, 0xff, 0xff])),
        U256::from(65_537u64)
    );
    assert_eq!(work(all_ones_below(1)), U256::from(1u64) << 255);
}

#[test]
fn target_zero_has_saturated_work() {
    assert_eq!(block_work(&Target([0; 32])), Work(U256::MAX));
}

#[test]
fn target_bytes_are_big_endian() {
    let target = target_with_top_bits(&[0, 1]);
    assert_eq!(target.to_u256(), U256::from(1u64) << 240);
    assert_eq!(Target::from_u256(U256::from(1u64) << 240), target);
}

#[test]
fn cumulative_work_adds_and_reports_overflow() {
    let total = CumWork::ZERO.checked_add(Work(U256::from(5u64))).unwrap();
    assert_eq!(total, CumWork(U256::from(5u64)));
    assert!(total > CumWork::ZERO);
    assert_eq!(CumWork(U256::MAX).checked_add(Work(U256::from(1u64))), None);
    assert_eq!(
        total.checked_sub(CumWork(U256::from(2u64))),
        Some(CumWork(U256::from(3u64)))
    );
    assert_eq!(CumWork::ZERO.checked_sub(total), None);
}

#[test]
fn circuit_limit_counts_the_key_and_the_circuit_together() {
    let k = key(1);
    let half = MAX_CIRCUIT_BYTES / 2 + 1;
    let tx = SignedTx {
        body: body(
            &k,
            0,
            TxKind::RegisterCircuit {
                system: ProofSystem::Groth16,
                constraint_count: ConstraintCount(1),
                verifying_key: vec![0; half].into_boxed_slice(),
                circuit: vec![0; half].into_boxed_slice(),
            },
        ),
        signature: pouw_crypto::Signature([0; 64]),
    };
    assert!(matches!(verify_tx(&tx), Err(TxError::OverLimit { .. })));
}

#[test]
fn proof_hash_has_its_own_prefix() {
    let block = sample_block();
    let hash = proof_tx_hash(&block.proof_txs[0]);
    let text = hash.to_string();
    assert!(text.starts_with("proof:"));
    assert_eq!(text.parse::<ProofHash>().unwrap(), hash);
    assert!(text.replace("proof:", "tx:").parse::<ProofHash>().is_err());
}

#[test]
fn enum_tags_match_serde() {
    for system in [
        ProofSystem::Groth16,
        ProofSystem::PlonkKzg,
        ProofSystem::Marlin,
    ] {
        assert_eq!(
            serde_json::to_value(system).unwrap(),
            serde_json::Value::from(system.as_str())
        );
    }
    let block = sample_block();
    for tx in &block.txs {
        let value = serde_json::to_value(&tx.body).unwrap();
        assert_eq!(value["kind"], tx.body.kind.name());
    }
}

mod properties {
    use pouw_crypto::{Address, FieldInput, Hash32, Signature};
    use proptest::{collection::vec, prelude::*};
    use ruint::aliases::U512;
    use zerocopy::{FromBytes, IntoBytes};

    use crate::*;

    fn bytes(max: usize) -> impl Strategy<Value = Box<[u8]>> {
        vec(any::<u8>(), 0..max).prop_map(Vec::into_boxed_slice)
    }

    fn address() -> impl Strategy<Value = Address> {
        any::<[u8; 32]>().prop_map(Address)
    }

    fn system() -> impl Strategy<Value = ProofSystem> {
        prop_oneof![
            Just(ProofSystem::Groth16),
            Just(ProofSystem::PlonkKzg),
            Just(ProofSystem::Marlin),
        ]
    }

    fn proof_request() -> impl Strategy<Value = TxKind> {
        (
            any::<[u8; 32]>(),
            vec(any::<[u8; 31]>().prop_map(FieldInput), 0..4),
            bytes(64),
        )
            .prop_map(|(circuit, public_inputs, witness)| TxKind::ProofRequest {
                circuit: CircuitId(TxId(Hash32(circuit))),
                public_inputs,
                witness,
            })
    }

    fn kind() -> impl Strategy<Value = TxKind> {
        prop_oneof![
            (address(), any::<u64>()).prop_map(|(to, amount)| TxKind::Transfer {
                to,
                amount: Amount(amount),
            }),
            proof_request(),
            (system(), any::<u64>(), bytes(64), bytes(64)).prop_map(
                |(system, count, verifying_key, circuit)| TxKind::RegisterCircuit {
                    system,
                    constraint_count: ConstraintCount(count),
                    verifying_key,
                    circuit,
                }
            ),
        ]
    }

    fn signed(kind: impl Strategy<Value = TxKind>) -> impl Strategy<Value = SignedTx> {
        (
            any::<u32>(),
            address(),
            any::<u64>(),
            any::<u64>(),
            kind,
            vec(any::<u8>(), 64),
        )
            .prop_map(|(chain, sender, nonce, fee, kind, sig)| {
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&sig);
                SignedTx {
                    body: TxBody {
                        chain_id: ChainId(chain),
                        sender,
                        nonce: Nonce(nonce),
                        fee: Amount(fee),
                        kind,
                    },
                    signature: Signature(signature),
                }
            })
    }

    fn proof_tx() -> impl Strategy<Value = ProofTx> {
        (signed(proof_request()), any::<u64>(), bytes(256)).prop_map(|(request, counter, proof)| {
            ProofTx {
                request,
                usage_counter: UsageCounter(counter),
                proof,
            }
        })
    }

    fn header() -> impl Strategy<Value = BlockHeader> {
        (
            (any::<u32>(), any::<u32>(), any::<u64>(), any::<u64>()),
            (any::<[u8; 32]>(), any::<u64>(), address()),
            (any::<[u8; 32]>(), any::<[u8; 32]>(), any::<u64>()),
        )
            .prop_map(
                |(
                    (version, chain_id, system_id, height),
                    (parent, timestamp, miner),
                    (root, target, nonce),
                )| BlockHeader {
                    version: U32::new(version),
                    chain_id: U32::new(chain_id),
                    system_id: U64::new(system_id),
                    height: U64::new(height),
                    parent: BlockId(Hash32(parent)),
                    timestamp: U64::new(timestamp),
                    miner,
                    tx_root: Hash32(root),
                    target: Target(target),
                    nonce: U64::new(nonce),
                },
            )
    }

    fn block() -> impl Strategy<Value = Block> {
        (header(), vec(signed(kind()), 0..4), vec(proof_tx(), 0..4)).prop_map(
            |(header, txs, proof_txs)| Block {
                header,
                txs,
                proof_txs,
            },
        )
    }

    proptest! {
        #[test]
        fn signed_tx_borsh_and_json_round_trip(tx in signed(kind())) {
            let bytes = borsh::to_vec(&tx).unwrap();
            prop_assert_eq!(bytes.len(), encoded_len(&tx));
            prop_assert_eq!(&borsh::from_slice::<SignedTx>(&bytes).unwrap(), &tx);
            let json = serde_json::to_string(&tx).unwrap();
            prop_assert_eq!(&serde_json::from_str::<SignedTx>(&json).unwrap(), &tx);
        }

        #[test]
        fn header_is_always_168_bytes(header in header()) {
            let bytes = borsh::to_vec(&header).unwrap();
            prop_assert_eq!(bytes.len(), 168);
            prop_assert_eq!(borsh::from_slice::<BlockHeader>(&bytes).unwrap(), header);
        }

        #[test]
        fn header_bytes_equal_borsh_for_any_header(header in header()) {
            prop_assert_eq!(header.as_bytes(), borsh::to_vec(&header).unwrap());
            prop_assert_eq!(BlockHeader::ref_from_bytes(header.as_bytes()).unwrap(), &header);
        }

        #[test]
        fn block_borsh_and_json_round_trip(block in block()) {
            let bytes = borsh::to_vec(&block).unwrap();
            prop_assert_eq!(&borsh::from_slice::<Block>(&bytes).unwrap(), &block);
            let json = serde_json::to_string(&block).unwrap();
            prop_assert_eq!(&serde_json::from_str::<Block>(&json).unwrap(), &block);
        }

        #[test]
        fn trailing_bytes_are_rejected(tx in signed(kind()), extra in any::<u8>()) {
            let mut bytes = borsh::to_vec(&tx).unwrap();
            bytes.push(extra);
            prop_assert!(borsh::from_slice::<SignedTx>(&bytes).is_err());
        }

        #[test]
        fn ids_round_trip_through_text(bytes in any::<[u8; 32]>()) {
            let id = TxId(Hash32(bytes));
            prop_assert_eq!(id.to_string().parse::<TxId>().unwrap(), id);
            let hash = BlockId(Hash32(bytes));
            prop_assert_eq!(hash.to_string().parse::<BlockId>().unwrap(), hash);
            let circuit = CircuitId(TxId(Hash32(bytes)));
            prop_assert_eq!(circuit.to_string().parse::<CircuitId>().unwrap(), circuit);
            let proof = ProofHash(Hash32(bytes));
            prop_assert_eq!(proof.to_string().parse::<ProofHash>().unwrap(), proof);
        }

        #[test]
        fn block_work_is_floor_of_two_pow_256_over_target_plus_one(bytes in any::<[u8; 32]>()) {
            let target = Target(bytes);
            prop_assume!(target.to_u256() != U256::ZERO);
            let work = block_work(&target).0.to::<U512>();
            let one = U512::from(1u64);
            let divisor = target.to_u256().to::<U512>().checked_add(one).unwrap();
            let two_pow_256 = one.checked_shl(256).unwrap();
            prop_assert!(work.checked_mul(divisor).unwrap() <= two_pow_256);
            prop_assert!(two_pow_256 < work.checked_add(one).unwrap().checked_mul(divisor).unwrap());
        }
    }
}

#[test]
fn versioned_read_accepts_the_current_version() {
    let header = sample_block().header;
    let read = BlockHeader::ref_from_versioned(header.as_bytes()).unwrap();
    assert_eq!(read, &header);
}

#[test]
fn versioned_read_rejects_an_unknown_version() {
    let mut header = sample_block().header;
    header.version = zerocopy::little_endian::U32::new(2);
    assert_eq!(
        BlockHeader::ref_from_versioned(header.as_bytes()),
        Err(HeaderError::UnknownVersion(2))
    );
}

#[test]
fn versioned_read_rejects_short_and_long_input() {
    let header = sample_block().header;
    let bytes = header.as_bytes();
    assert_eq!(
        BlockHeader::ref_from_versioned(&bytes[..3]),
        Err(HeaderError::TooShort { found: 3 })
    );
    assert_eq!(
        BlockHeader::ref_from_versioned(&bytes[1..]),
        Err(HeaderError::UnknownVersion(u32::from_le_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4]
        ])))
    );
    assert_eq!(
        BlockHeader::ref_from_versioned(&bytes[..100]),
        Err(HeaderError::BadLength { found: 100 })
    );
}

#[test]
fn a_stored_block_starts_with_its_header_bytes() {
    let block = sample_block();
    let stored = borsh::to_vec(&block).unwrap();
    let (header, rest) = BlockHeader::ref_from_prefix(&stored).unwrap();
    assert_eq!(header, &block.header);
    assert_eq!(block_id(header), block_id(&block.header));
    assert_eq!(
        rest,
        borsh::to_vec(&(&block.txs, &block.proof_txs)).unwrap()
    );
}

#[test]
fn borsh_reads_exactly_the_header_size() {
    let header = sample_block().header;
    let bytes = borsh::to_vec(&header).unwrap();
    assert_eq!(bytes.len(), BlockHeader::SIZE);
    assert_eq!(BlockHeader::SIZE, 168);
    assert_eq!(borsh::from_slice::<BlockHeader>(&bytes).unwrap(), header);
    assert!(borsh::from_slice::<BlockHeader>(&bytes[..167]).is_err());
    let mut long = bytes.clone();
    long.push(0);
    assert!(borsh::from_slice::<BlockHeader>(&long).is_err());
}

fn id_with_prefix(prefix: [u8; 4]) -> TxId {
    let mut bytes = [0xAB_u8; 32];
    for (byte, value) in bytes.iter_mut().zip(prefix) {
        *byte = value;
    }
    TxId(Hash32(bytes))
}

#[test]
fn a_request_falls_into_the_bucket_of_its_hash_prefix() {
    // The prefix 01 02 03 04 read little-endian is 0x0403_0201 = 67_305_985.
    let id = id_with_prefix([1, 2, 3, 4]);
    assert_eq!(bucket(&id, 10), Some(5));
    assert_eq!(bucket(&id, 4), Some(1));
    assert_eq!(bucket(&id, 1), Some(0));
    // Only the first 4 bytes count.
    let mut other = id.hash().0;
    if let Some(byte) = other.get_mut(4) {
        *byte ^= 0xFF;
    }
    assert_eq!(bucket(&TxId(Hash32(other)), 10), Some(5));
}

#[test]
fn the_bucket_is_right_at_the_edges_of_the_prefix() {
    // The largest prefix is u32::MAX = 4_294_967_295.
    let top = id_with_prefix([0xFF; 4]);
    assert_eq!(bucket(&top, 7), Some(3));
    assert_eq!(bucket(&top, u32::MAX), Some(0));
    assert_eq!(bucket(&top, u32::MAX - 1), Some(1));
    // The smallest prefix is in bucket 0 whatever the count.
    let zero = id_with_prefix([0; 4]);
    assert_eq!(bucket(&zero, 1000), Some(0));
    // A prefix equal to the count wraps to bucket 0, one more is bucket 1.
    assert_eq!(bucket(&id_with_prefix([10, 0, 0, 0]), 10), Some(0));
    assert_eq!(bucket(&id_with_prefix([11, 0, 0, 0]), 10), Some(1));
}

#[test]
fn no_request_has_a_bucket_among_zero_buckets() {
    assert_eq!(bucket(&id_with_prefix([1, 2, 3, 4]), 0), None);
}

#[test]
fn one_bucket_holds_every_request() {
    assert_eq!(TEMPORARY_BUCKET_COUNT, 1);
    for prefix in [[0; 4], [1, 2, 3, 4], [0xFF; 4]] {
        assert_eq!(
            bucket(&id_with_prefix(prefix), TEMPORARY_BUCKET_COUNT),
            Some(0)
        );
    }
}
