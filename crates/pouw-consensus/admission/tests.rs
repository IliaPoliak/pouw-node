use pouw_crypto::{Address, FieldInput, Hash32, SigningKey};
use pouw_types::{
    Account, Amount, ChainId, CircuitEntry, CircuitId, ConsensusParams, ConstraintCount, Height,
    Nonce, ProofSystem, SignedTx, Target, TxBody, TxId, TxKind, sign_body,
};

use crate::{
    InvalidTx, MemState,
    admission::{AdmissionError, check_admission, cost, minimum_fee},
};

const CHAIN: ChainId = ChainId(7);
const BOB: Address = Address([5; 32]);
const CIRCUIT: CircuitId = CircuitId(TxId(Hash32([3; 32])));

fn params(per_input: u64, per_kib: u64) -> ConsensusParams {
    ConsensusParams {
        chain_id: CHAIN,
        initial_subsidy: Amount(50),
        halving_interval: 100,
        target_block_secs: 10,
        half_life_secs: 100,
        initial_target: Target([0xff; 32]),
        pow_limit: Target([0xff; 32]),
        max_future_secs: 300,
        fee_per_public_input: Amount(per_input),
        fee_per_witness_kib: Amount(per_kib),
    }
}

fn key() -> SigningKey {
    SigningKey::from_seed([1; 32])
}

fn tx(nonce: u64, fee: u64, kind: TxKind) -> SignedTx {
    let key = key();
    sign_body(
        &TxBody {
            chain_id: CHAIN,
            sender: key.address(),
            nonce: Nonce(nonce),
            fee: Amount(fee),
            kind,
        },
        &key,
    )
}

fn transfer(nonce: u64, fee: u64, amount: u64) -> SignedTx {
    tx(
        nonce,
        fee,
        TxKind::Transfer {
            to: BOB,
            amount: Amount(amount),
        },
    )
}

fn request(nonce: u64, fee: u64, inputs: usize, witness: usize) -> SignedTx {
    tx(
        nonce,
        fee,
        TxKind::ProofRequest {
            circuit: CIRCUIT,
            public_inputs: vec![FieldInput([4; 31]); inputs],
            witness: vec![0; witness].into_boxed_slice(),
        },
    )
}

/// The sender holds `balance` with the account nonce `nonce`, `CIRCUIT` is registered.
fn state(balance: u64, nonce: u64) -> MemState {
    let mut state = MemState::default();
    state.accounts.insert(
        key().address(),
        Account {
            balance: Amount(balance),
            nonce: Nonce(nonce),
        },
    );
    state.circuits.insert(
        CIRCUIT,
        CircuitEntry {
            id: CIRCUIT,
            system: ProofSystem::Groth16,
            constraint_count: ConstraintCount(1),
            owner: BOB,
            registered_at: Height(0),
            verifying_key: Box::from([1]),
            circuit: Box::from([2]),
        },
    );
    state
}

fn rejected(result: Result<(), AdmissionError>) -> InvalidTx {
    match result {
        Err(AdmissionError::Invalid(error)) => error,
        other => panic!("expected a rejection, found {other:?}"),
    }
}

fn check(state: &MemState, tx: &SignedTx, queued: &[&TxBody]) -> Result<(), AdmissionError> {
    check_admission(&params(1, 1), state, tx, queued)
}

#[test]
fn a_funded_transfer_with_the_account_nonce_is_admitted() {
    assert_eq!(check(&state(100, 0), &transfer(0, 1, 99), &[]), Ok(()));
}

#[test]
fn a_higher_nonce_is_admitted_and_a_lower_one_is_not() {
    let state = state(100, 2);
    assert_eq!(check(&state, &transfer(5, 1, 1), &[]), Ok(()));
    assert_eq!(
        rejected(check(&state, &transfer(1, 1, 1), &[])),
        InvalidTx::BadNonce {
            expected: Nonce(2),
            found: Nonce(1)
        }
    );
}

#[test]
fn a_transfer_over_the_balance_is_rejected() {
    assert_eq!(
        rejected(check(&state(100, 0), &transfer(0, 1, 100), &[])),
        InvalidTx::InsufficientBalance {
            needed: Amount(101),
            available: Amount(100)
        }
    );
}

#[test]
fn an_unknown_sender_has_no_balance() {
    let result = check(&MemState::default(), &transfer(0, 1, 1), &[]);
    assert_eq!(
        rejected(result),
        InvalidTx::InsufficientBalance {
            needed: Amount(2),
            available: Amount(0)
        }
    );
}

#[test]
fn the_pending_transactions_of_the_sender_count_against_the_balance() {
    let state = state(100, 0);
    let first = transfer(0, 1, 60);
    let second = transfer(1, 1, 38);
    assert_eq!(check(&state, &second, &[&first.body]), Ok(()));
    let third = transfer(1, 1, 39);
    assert_eq!(
        rejected(check(&state, &third, &[&first.body])),
        InvalidTx::InsufficientBalance {
            needed: Amount(101),
            available: Amount(100)
        }
    );
}

#[test]
fn a_request_for_an_unregistered_circuit_is_rejected() {
    let state = MemState {
        circuits: pouw_types::FastMap::default(),
        ..state(100, 0)
    };
    assert_eq!(
        rejected(check(&state, &request(0, 10, 1, 1), &[])),
        InvalidTx::UnknownCircuit(CIRCUIT)
    );
}

#[test]
fn a_request_below_the_minimum_fee_is_rejected() {
    // 2 inputs at 1 and 2 started KiB at 1: the minimum is 4.
    let state = state(100, 0);
    assert_eq!(check(&state, &request(0, 4, 2, 1025), &[]), Ok(()));
    assert_eq!(
        rejected(check(&state, &request(0, 3, 2, 1025), &[])),
        InvalidTx::FeeTooLow {
            minimum: Amount(4),
            found: Amount(3)
        }
    );
}

#[test]
fn the_minimum_fee_counts_started_kibibytes_and_only_for_requests() {
    let p = params(3, 5);
    let kind = |inputs, witness| request(0, 0, inputs, witness).body.kind;
    assert_eq!(minimum_fee(&p, &kind(0, 0)), Some(Amount(0)));
    assert_eq!(minimum_fee(&p, &kind(0, 1)), Some(Amount(5)));
    assert_eq!(minimum_fee(&p, &kind(0, 1024)), Some(Amount(5)));
    assert_eq!(minimum_fee(&p, &kind(2, 1025)), Some(Amount(16)));
    assert_eq!(
        minimum_fee(&p, &transfer(0, 0, 1).body.kind),
        Some(Amount(0))
    );
}

#[test]
fn an_overflowing_cost_is_rejected() {
    assert_eq!(
        rejected(check(&state(100, 0), &transfer(0, u64::MAX, 1), &[])),
        InvalidTx::BalanceOverflow
    );
    assert_eq!(cost(&transfer(0, u64::MAX, 1).body), None);
}

#[test]
fn a_request_pays_only_its_fee_from_the_balance() {
    assert_eq!(check(&state(10, 0), &request(0, 10, 1, 1), &[]), Ok(()));
    assert_eq!(
        rejected(check(&state(9, 0), &request(0, 10, 1, 1), &[])),
        InvalidTx::InsufficientBalance {
            needed: Amount(10),
            available: Amount(9)
        }
    );
}
