use pouw_crypto::{Address, FieldInput, Hash32, SigningKey};
use pouw_types::{
    Account, Amount, Block, BlockHeader, BlockId, ChainId, CircuitId, ConsensusParams,
    ConstraintCount, Height, Nonce, ProofSystem, ProofTx, SignedTx, Target, TxBody, TxId, TxKind,
    U32, U64, UsageCounter, sign_body, txid,
};

use crate::{
    BlockError, InvalidBlock, InvalidTx, MemState, StateDiff, apply_block,
    state::{self, Change},
};

const CHAIN: ChainId = ChainId(7);
const MINER: Address = Address([9; 32]);
const BOB: Address = Address([5; 32]);

fn params() -> ConsensusParams {
    ConsensusParams {
        chain_id: CHAIN,
        initial_subsidy: Amount(50),
        halving_interval: 100,
        target_block_secs: 10,
        half_life_secs: 100,
        initial_target: Target([0xff; 32]),
        pow_limit: Target([0xff; 32]),
        max_future_secs: 300,
        fee_per_public_input: Amount(0),
        fee_per_witness_kib: Amount(0),
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_seed([seed; 32])
}

fn alice() -> Address {
    key(1).address()
}

fn signed(seed: u8, nonce: u64, kind: TxKind) -> SignedTx {
    let key = key(seed);
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

fn transfer(seed: u8, nonce: u64, to: Address, amount: u64) -> SignedTx {
    signed(
        seed,
        nonce,
        TxKind::Transfer {
            to,
            amount: Amount(amount),
        },
    )
}

fn register(seed: u8, nonce: u64) -> SignedTx {
    signed(
        seed,
        nonce,
        TxKind::RegisterCircuit {
            system: ProofSystem::Groth16,
            constraint_count: ConstraintCount(1),
            verifying_key: Box::from([1]),
            circuit: Box::from([2]),
        },
    )
}

fn request(seed: u8, nonce: u64, circuit: CircuitId) -> SignedTx {
    signed(
        seed,
        nonce,
        TxKind::ProofRequest {
            circuit,
            public_inputs: vec![FieldInput([4; 31])],
            witness: Box::from([5]),
        },
    )
}

fn proof_tx(request: SignedTx, counter: u64) -> ProofTx {
    ProofTx {
        request,
        usage_counter: UsageCounter(counter),
        proof: Box::from([0xaa; 32]),
    }
}

fn block(txs: Vec<SignedTx>, proof_txs: Vec<ProofTx>) -> Block {
    Block {
        header: BlockHeader {
            version: U32::new(1),
            chain_id: U32::new(CHAIN.0),
            system_id: U64::new(0),
            height: U64::new(1),
            parent: BlockId::ZERO,
            timestamp: U64::new(100),
            miner: MINER,
            tx_root: Hash32::ZERO,
            target: Target([0xff; 32]),
            nonce: U64::new(0),
        },
        txs,
        proof_txs,
    }
}

/// A state where `alice()` holds `balance` and has sent nothing.
fn funded(balance: u64) -> MemState {
    let mut state = MemState::default();
    state.accounts.insert(
        alice(),
        Account {
            balance: Amount(balance),
            nonce: Nonce(0),
        },
    );
    state
}

fn run(state: &MemState, block: &Block) -> Result<StateDiff, BlockError> {
    let mut ids = Vec::new();
    block.txids_into(&mut ids);
    apply_block(&params(), state, block, &ids)
}

fn invalid(result: Result<StateDiff, BlockError>) -> InvalidBlock {
    match result {
        Err(BlockError::Invalid(error)) => error,
        other => panic!("expected an invalid block, found {other:?}"),
    }
}

fn balance(state: &MemState, address: &Address) -> Option<Amount> {
    state.accounts.get(address).map(|account| account.balance)
}

#[test]
fn a_transfer_moves_the_balances_and_the_nonce_and_pays_the_miner() {
    let before = funded(100);
    let diff = run(&before, &block(vec![transfer(1, 0, BOB, 30)], vec![])).unwrap();
    let mut after = before.clone();
    state::apply(&mut after, &diff).unwrap();
    assert_eq!(balance(&after, &alice()), Some(Amount(69)));
    assert_eq!(after.accounts[&alice()].nonce, Nonce(1));
    assert_eq!(balance(&after, &BOB), Some(Amount(30)));
    // the subsidy of height 1 plus the fee of the transfer
    assert_eq!(balance(&after, &MINER), Some(Amount(51)));

    state::apply(&mut after, &diff.inverse()).unwrap();
    assert_eq!(after, before);
}

#[test]
fn an_empty_block_pays_only_the_subsidy() {
    let before = funded(100);
    let diff = run(&before, &block(vec![], vec![])).unwrap();
    let mut after = before.clone();
    state::apply(&mut after, &diff).unwrap();
    assert_eq!(balance(&after, &MINER), Some(Amount(50)));
    assert_eq!(balance(&after, &alice()), Some(Amount(100)));
}

#[test]
fn a_transfer_to_oneself_costs_only_the_fee() {
    let before = funded(100);
    let diff = run(&before, &block(vec![transfer(1, 0, alice(), 40)], vec![])).unwrap();
    let mut after = before.clone();
    state::apply(&mut after, &diff).unwrap();
    assert_eq!(balance(&after, &alice()), Some(Amount(99)));
    assert_eq!(after.accounts[&alice()].nonce, Nonce(1));
}

#[test]
fn a_later_transaction_sees_an_earlier_one() {
    let before = funded(100);
    let txs = vec![transfer(1, 0, BOB, 10), transfer(1, 1, BOB, 10)];
    let diff = run(&before, &block(txs, vec![])).unwrap();
    let mut after = before.clone();
    state::apply(&mut after, &diff).unwrap();
    assert_eq!(balance(&after, &alice()), Some(Amount(78)));
    assert_eq!(after.accounts[&alice()].nonce, Nonce(2));
    assert_eq!(balance(&after, &BOB), Some(Amount(20)));
}

#[test]
fn a_wrong_nonce_is_refused() {
    let result = run(&funded(100), &block(vec![transfer(1, 5, BOB, 1)], vec![]));
    assert_eq!(
        invalid(result),
        InvalidBlock::Tx {
            proof: false,
            index: 0,
            source: InvalidTx::BadNonce {
                expected: Nonce(0),
                found: Nonce(5),
            },
        }
    );
}

#[test]
fn a_transfer_the_balance_does_not_cover_is_refused() {
    let result = run(&funded(10), &block(vec![transfer(1, 0, BOB, 30)], vec![]));
    assert_eq!(
        invalid(result),
        InvalidBlock::Tx {
            proof: false,
            index: 0,
            source: InvalidTx::InsufficientBalance {
                needed: Amount(31),
                available: Amount(10),
            },
        }
    );
}

#[test]
fn an_unfunded_sender_is_refused() {
    let result = run(
        &MemState::default(),
        &block(vec![transfer(1, 0, BOB, 1)], vec![]),
    );
    assert!(matches!(
        invalid(result),
        InvalidBlock::Tx {
            source: InvalidTx::InsufficientBalance { .. },
            ..
        }
    ));
}

#[test]
fn a_proof_request_in_txs_is_refused() {
    let circuit = CircuitId(TxId(Hash32([3; 32])));
    let result = run(&funded(100), &block(vec![request(1, 0, circuit)], vec![]));
    assert_eq!(
        invalid(result),
        InvalidBlock::Tx {
            proof: false,
            index: 0,
            source: InvalidTx::WrongKind {
                kind: "proof_request",
                place: "txs",
            },
        }
    );
}

#[test]
fn a_transfer_as_a_proof_request_is_refused() {
    let result = run(
        &funded(100),
        &block(vec![], vec![proof_tx(transfer(1, 0, BOB, 1), 0)]),
    );
    assert!(matches!(
        invalid(result),
        InvalidBlock::Tx {
            proof: true,
            index: 0,
            source: InvalidTx::WrongKind { .. },
        }
    ));
}

#[test]
fn a_request_for_an_unregistered_circuit_is_refused() {
    let circuit = CircuitId(TxId(Hash32([3; 32])));
    let result = run(
        &funded(100),
        &block(vec![], vec![proof_tx(request(1, 0, circuit), 0)]),
    );
    assert_eq!(
        invalid(result),
        InvalidBlock::Tx {
            proof: true,
            index: 0,
            source: InvalidTx::UnknownCircuit(circuit),
        }
    );
}

#[test]
fn a_circuit_registered_in_the_block_can_be_requested_in_the_same_block() {
    let registration = register(1, 0);
    let circuit = CircuitId(txid(&registration));
    let before = funded(100);
    let candidate = block(
        vec![registration],
        vec![proof_tx(request(1, 1, circuit), 0)],
    );
    let diff = run(&before, &candidate).unwrap();
    let mut after = before.clone();
    state::apply(&mut after, &diff).unwrap();

    let entry = &after.circuits[&circuit];
    assert_eq!(entry.owner, alice());
    assert_eq!(entry.registered_at, Height(1));
    assert_eq!(entry.system, ProofSystem::Groth16);
    assert_eq!(after.usage_counters[&(MINER, circuit)], UsageCounter(0));
    assert_eq!(after.accounts[&alice()].nonce, Nonce(2));
    // two fees of 1 and the subsidy
    assert_eq!(balance(&after, &alice()), Some(Amount(98)));
    assert_eq!(balance(&after, &MINER), Some(Amount(52)));

    state::apply(&mut after, &diff.inverse()).unwrap();
    assert_eq!(after, before);
}

#[test]
fn the_usage_counter_starts_at_zero_and_goes_up_by_one() {
    let registration = register(1, 0);
    let circuit = CircuitId(txid(&registration));
    let wrong_start = block(
        vec![registration.clone()],
        vec![proof_tx(request(1, 1, circuit), 3)],
    );
    assert_eq!(
        invalid(run(&funded(100), &wrong_start)),
        InvalidBlock::BadUsageCounter {
            index: 0,
            expected: UsageCounter(0),
            found: UsageCounter(3),
        }
    );

    // a state where the miner already proved this circuit four times
    let mut state = funded(100);
    let before = block(vec![registration], vec![]);
    let diff = run(&state, &before).unwrap();
    state::apply(&mut state, &diff).unwrap();
    state
        .usage_counters
        .insert((MINER, circuit), UsageCounter(4));
    let next = block(vec![], vec![proof_tx(request(1, 1, circuit), 5)]);
    let diff = run(&state, &next).unwrap();
    assert_eq!(
        diff.usage_counters[&(MINER, circuit)],
        Change {
            before: Some(UsageCounter(4)),
            after: Some(UsageCounter(5)),
        }
    );
}

#[test]
fn txids_that_do_not_match_the_block_are_a_state_fault() {
    let result = apply_block(
        &params(),
        &funded(100),
        &block(vec![transfer(1, 0, BOB, 1)], vec![]),
        &[],
    );
    assert!(matches!(result, Err(BlockError::State(_))));
}
