//! Consensus of PoUW-ZK as pure functions: the chain state and its diffs,
//! the validity rules of `contracts/block.md`, and the research
//! seams: proof of work (`pow`), target (`difficulty`), timestamp, fork choice,
//! subsidy (`reward`) and the state transition of a block (`transition`). Nothing
//! here does I/O, reads a clock or spawns a task, so every node computes the same
//! result from the same inputs and every rule is testable without a node.

#![forbid(unsafe_code)]

pub mod admission;
pub mod difficulty;
pub mod fork_choice;
pub mod pow;
pub mod reward;
pub mod state;
pub mod timestamp;
pub mod transition;
pub mod validation;

pub use admission::{AdmissionError, check_admission, minimum_fee};
pub use difficulty::{Anchor, DifficultyError, next_target};
pub use fork_choice::{ChainTip, better};
pub use pouw_types::ConsensusParams;
pub use pow::{PowError, check as check_pow, verify as verify_pow};
pub use reward::subsidy;
pub use state::{ChainState, Change, DiffMismatch, MemState, StateDiff, StateError, StateView};
pub use timestamp::{TimestampError, median_time_past};
pub use transition::apply_block;
pub use validation::{
    BlockError, HeaderContext, InvalidBlock, InvalidTx, Scratch, check_body, check_header,
    check_tx, check_tx_with,
};

#[cfg(test)]
mod tests;
