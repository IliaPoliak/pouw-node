//! Research seam: the stateful admission check of a transaction that enters the
//! mempool (pouw-node#66). It applies the rules of block.md that read the state to one
//! transaction against the state at the tip, plus the minimum fee of a proof request.
//! The checks of a block are in [`crate::apply_block`] and use the same error type.

use pouw_types::{Amount, ConsensusParams, SignedTx, TxBody, TxKind};
use thiserror::Error;

use crate::{InvalidTx, StateError, StateView};

/// Why a transaction was not admitted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AdmissionError {
    /// The transaction breaks a rule, the sender gets the reason.
    #[error(transparent)]
    Invalid(#[from] InvalidTx),
    /// The state could not be read, a node fault.
    #[error(transparent)]
    State(#[from] StateError),
}

/// The fee a proof request must pay at least: `fee_per_public_input` per public input
/// element plus `fee_per_witness_kib` per started KiB of witness. Other kinds have no
/// minimum. `None` when the sum overflows.
pub fn minimum_fee(params: &ConsensusParams, kind: &TxKind) -> Option<Amount> {
    let TxKind::ProofRequest {
        public_inputs,
        witness,
        ..
    } = kind
    else {
        return Some(Amount(0));
    };
    let inputs = u64::try_from(public_inputs.len()).ok()?;
    let kibs = u64::try_from(witness.len().div_ceil(1024)).ok()?;
    let by_inputs = params.fee_per_public_input.0.checked_mul(inputs)?;
    let by_witness = params.fee_per_witness_kib.0.checked_mul(kibs)?;
    by_inputs.checked_add(by_witness).map(Amount)
}

/// What a transaction takes from the balance of its sender: the amount of a transfer
/// plus the fee. `None` when the sum overflows.
pub fn cost(body: &TxBody) -> Option<Amount> {
    match &body.kind {
        TxKind::Transfer { amount, .. } => amount.checked_add(body.fee),
        _ => Some(body.fee),
    }
}

/// Checks `tx` against the state `view` at the tip. `queued` are the bodies of the
/// pending transactions of the same sender with a lower nonce, which take their cost
/// from the balance first.
///
/// 1. The nonce is not below the nonce of the account (`InvalidTx::BadNonce`). A higher
///    nonce is admitted, the pool queues it behind the missing ones.
/// 2. A proof request pays at least [`minimum_fee`] (`FeeTooLow`).
/// 3. A proof request names a registered circuit (`UnknownCircuit`).
/// 4. The balance covers the cost of `tx` plus the cost of `queued`
///    (`InsufficientBalance`, `BalanceOverflow`).
///
/// # Errors
///
/// [`AdmissionError::Invalid`] for a broken rule, [`AdmissionError::State`] when the
/// state cannot be read.
pub fn check_admission<V: StateView + ?Sized>(
    params: &ConsensusParams,
    view: &V,
    tx: &SignedTx,
    queued: &[&TxBody],
) -> Result<(), AdmissionError> {
    let body = &tx.body;
    if !matches!(
        body.kind,
        TxKind::Transfer { .. } | TxKind::ProofRequest { .. } | TxKind::RegisterCircuit { .. }
    ) {
        return Err(InvalidTx::WrongKind {
            kind: "unknown",
            place: "the mempool",
        }
        .into());
    }
    let account = view.account(&body.sender)?.unwrap_or_default();
    if body.nonce < account.nonce {
        return Err(InvalidTx::BadNonce {
            expected: account.nonce,
            found: body.nonce,
        }
        .into());
    }
    if let TxKind::ProofRequest { circuit, .. } = &body.kind {
        let minimum = minimum_fee(params, &body.kind).ok_or(InvalidTx::BalanceOverflow)?;
        if body.fee < minimum {
            return Err(InvalidTx::FeeTooLow {
                minimum,
                found: body.fee,
            }
            .into());
        }
        if view.circuit(circuit)?.is_none() {
            return Err(InvalidTx::UnknownCircuit(*circuit).into());
        }
    }
    let mut needed = cost(body).ok_or(InvalidTx::BalanceOverflow)?;
    for earlier in queued {
        let each = cost(earlier).ok_or(InvalidTx::BalanceOverflow)?;
        needed = needed.checked_add(each).ok_or(InvalidTx::BalanceOverflow)?;
    }
    if needed > account.balance {
        return Err(InvalidTx::InsufficientBalance {
            needed,
            available: account.balance,
        }
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
