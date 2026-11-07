//! Research seam: the state transition of a block. [`apply_block`] is the stateful half
//! of the validity rules of `contracts/block.md`, the half that needs the account
//! state. The proof verify is a work job, `pouw-node` `miner::verify_work`.

use pouw_crypto::Address;
use pouw_types::{
    Amount, Block, CircuitEntry, CircuitId, ConsensusParams, Height, ProofTx, SignedTx, TxId,
    TxKind, UsageCounter,
};

use crate::{
    BlockError, ChainState, InvalidBlock, InvalidTx, StateDiff, StateError, StateView,
    reward::subsidy,
    state::{set_account, set_circuit, set_usage_counter},
};

/// The change `block` makes to the state `view`: nonces and balances of the senders,
/// the receivers of transfers, the registry, the usage counters and the reward of
/// `header.miner` (pouw-node#65, pouw-node#77).
///
/// Built over a [`ChainState`] whose `base` is `view` and whose `diff` is the result.
/// `txids` are the ids of `block.txs` followed by the ids of the requests of
/// `block.proof_txs`, the order `Block::txids_into` gives.
/// 1. For each transaction in block order (`block.txs`, then the request of each of
///    `block.proof_txs`): the nonce is the account's (`InvalidTx::BadNonce`), balance
///    covers amount plus fee (`InsufficientBalance`), a proof request names a
///    registered circuit (`UnknownCircuit`). A broken rule is
///    `InvalidBlock::Tx { proof, index, source }`, `index` the position in its list.
///    The sender's nonce goes up by one. A `RegisterCircuit` becomes a `CircuitEntry`
///    whose `id` is the transaction's entry of `txids`, `owner` the sender and
///    `registered_at` the block height. Writes go through `set_account`, `set_circuit`
///    and `set_usage_counter`, so a later transaction sees an earlier one.
///    A proof tx's `usage_counter` is `UsageCounter(0)` when the miner has no counter for
///    the circuit, else `checked_next` of it (`InvalidBlock::BadUsageCounter`).
/// 2. Money moves with `Amount::checked_add` and `checked_sub`, an overflow is an
///    invalid transaction (`BalanceOverflow`).
/// 3. Credit `reward::subsidy(params, height)` plus every fee to `header.miner`.
/// 4. `BlockError::Invalid` goes to the caller's `mark_failed`, `block_rejected` and
///    `BlockOutcome::Invalid`. `BlockError::State` and `BlockError::Prover` are a
///    node fault, never held against a peer.
///
/// The proof itself is not checked here, that is the work job `miner::verify_work`.
///
/// # Errors
///
/// [`BlockError::Invalid`] for a broken rule, [`BlockError::State`] when the state
/// cannot be read or `txids` do not match the block.
pub fn apply_block<V: StateView + ?Sized>(
    params: &ConsensusParams,
    view: &V,
    block: &Block,
    txids: &[TxId],
) -> Result<StateDiff, BlockError> {
    if txids.len() != block.txs.len().saturating_add(block.proof_txs.len()) {
        return Err(StateError::Corrupt("the txids do not match the block".to_owned()).into());
    }
    let height = Height(block.header.height.get());
    let miner = block.header.miner;
    let mut overlay = ChainState {
        base: view,
        diff: StateDiff::default(),
    };
    let mut fees = Amount(0);

    for (index, (tx, id)) in block.txs.iter().zip(txids).enumerate() {
        apply_tx(&mut overlay, tx, *id, height, &mut fees)
            .map_err(|fail| fail.in_block(false, index))?;
    }
    for (index, proof_tx) in block.proof_txs.iter().enumerate() {
        let circuit = apply_request(&mut overlay, &proof_tx.request, &mut fees)
            .map_err(|fail| fail.in_block(true, index))?;
        let expected = expected_counter(&overlay, &miner, &circuit, index, proof_tx)?;
        if proof_tx.usage_counter != expected {
            return Err(InvalidBlock::BadUsageCounter {
                index,
                expected,
                found: proof_tx.usage_counter,
            }
            .into());
        }
        set_usage_counter(&mut overlay, miner, circuit, expected)?;
    }

    let reward = subsidy(params, height)
        .checked_add(fees)
        .ok_or_else(|| StateError::Corrupt("the block reward overflows".to_owned()))?;
    if reward.0 > 0 {
        credit(&mut overlay, miner, reward).map_err(|fail| match fail {
            Fail::Tx(_) => BlockError::State(StateError::Corrupt(
                "the miner balance overflows".to_owned(),
            )),
            Fail::State(error) => BlockError::State(error),
        })?;
    }
    Ok(overlay.diff)
}

/// Why one transaction could not be applied.
enum Fail {
    /// The transaction breaks a rule.
    Tx(InvalidTx),
    /// The state could not be read.
    State(StateError),
}

impl From<InvalidTx> for Fail {
    fn from(error: InvalidTx) -> Self {
        Self::Tx(error)
    }
}

impl From<StateError> for Fail {
    fn from(error: StateError) -> Self {
        Self::State(error)
    }
}

impl Fail {
    fn in_block(self, proof: bool, index: usize) -> BlockError {
        match self {
            Fail::Tx(source) => InvalidBlock::Tx {
                proof,
                index,
                source,
            }
            .into(),
            Fail::State(error) => error.into(),
        }
    }
}

/// Checks the nonce and the balance of the sender, takes `amount` plus the fee from the
/// balance and raises the nonce.
fn spend<V: StateView + ?Sized>(
    overlay: &mut ChainState<'_, V>,
    tx: &SignedTx,
    amount: Amount,
) -> Result<(), Fail> {
    let body = &tx.body;
    let mut account = overlay.account(&body.sender)?.unwrap_or_default();
    if account.nonce != body.nonce {
        return Err(InvalidTx::BadNonce {
            expected: account.nonce,
            found: body.nonce,
        }
        .into());
    }
    let needed = amount
        .checked_add(body.fee)
        .ok_or(InvalidTx::BalanceOverflow)?;
    account.balance =
        account
            .balance
            .checked_sub(needed)
            .ok_or(InvalidTx::InsufficientBalance {
                needed,
                available: account.balance,
            })?;
    account.nonce = account.nonce.checked_next().ok_or(InvalidTx::BadNonce {
        expected: account.nonce,
        found: body.nonce,
    })?;
    set_account(overlay, body.sender, account)?;
    Ok(())
}

fn credit<V: StateView + ?Sized>(
    overlay: &mut ChainState<'_, V>,
    address: Address,
    amount: Amount,
) -> Result<(), Fail> {
    let mut account = overlay.account(&address)?.unwrap_or_default();
    account.balance = account
        .balance
        .checked_add(amount)
        .ok_or(InvalidTx::BalanceOverflow)?;
    set_account(overlay, address, account)?;
    Ok(())
}

/// One entry of `block.txs`.
fn apply_tx<V: StateView + ?Sized>(
    overlay: &mut ChainState<'_, V>,
    tx: &SignedTx,
    id: TxId,
    height: Height,
    fees: &mut Amount,
) -> Result<(), Fail> {
    match &tx.body.kind {
        TxKind::Transfer { to, amount } => {
            spend(overlay, tx, *amount)?;
            credit(overlay, *to, *amount)?;
        }
        TxKind::RegisterCircuit {
            system,
            constraint_count,
            verifying_key,
            circuit,
        } => {
            spend(overlay, tx, Amount(0))?;
            set_circuit(
                overlay,
                CircuitEntry {
                    id: CircuitId(id),
                    system: *system,
                    constraint_count: *constraint_count,
                    owner: tx.body.sender,
                    registered_at: height,
                    verifying_key: verifying_key.clone(),
                    circuit: circuit.clone(),
                },
            )?;
        }
        TxKind::ProofRequest { .. } => {
            return Err(InvalidTx::WrongKind {
                kind: "proof_request",
                place: "txs",
            }
            .into());
        }
        _ => {
            return Err(InvalidTx::WrongKind {
                kind: "unknown",
                place: "txs",
            }
            .into());
        }
    }
    *fees = fees
        .checked_add(tx.body.fee)
        .ok_or(InvalidTx::BalanceOverflow)?;
    Ok(())
}

/// The request of one proof tx: it pays its fee and names a registered circuit, which
/// is returned.
fn apply_request<V: StateView + ?Sized>(
    overlay: &mut ChainState<'_, V>,
    request: &SignedTx,
    fees: &mut Amount,
) -> Result<CircuitId, Fail> {
    let TxKind::ProofRequest { circuit, .. } = &request.body.kind else {
        return Err(InvalidTx::WrongKind {
            kind: "non proof_request",
            place: "the request of a proof tx",
        }
        .into());
    };
    spend(overlay, request, Amount(0))?;
    if overlay.circuit(circuit)?.is_none() {
        return Err(InvalidTx::UnknownCircuit(*circuit).into());
    }
    *fees = fees
        .checked_add(request.body.fee)
        .ok_or(InvalidTx::BalanceOverflow)?;
    Ok(*circuit)
}

/// The counter the next proof of `miner` for `circuit` must carry.
fn expected_counter<V: StateView + ?Sized>(
    overlay: &ChainState<'_, V>,
    miner: &Address,
    circuit: &CircuitId,
    index: usize,
    proof_tx: &ProofTx,
) -> Result<UsageCounter, BlockError> {
    match overlay.usage_counter(miner, circuit)? {
        None => Ok(UsageCounter(0)),
        Some(last) => last.checked_next().ok_or_else(|| {
            InvalidBlock::BadUsageCounter {
                index,
                expected: last,
                found: proof_tx.usage_counter,
            }
            .into()
        }),
    }
}

#[cfg(test)]
mod tests;
