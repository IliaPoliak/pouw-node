//! Wire and state types of the PoUW-ZK chain as fixed by `contracts/block.md`:
//! transactions, blocks, identifiers, quantities and the protocol constants. The hash
//! rules (txid, block id, block work, proof hash, Merkle root, eta, mask) live here, so
//! every component derives them the same way. Nothing outside this crate encodes or
//! hashes protocol data by hand.

#![forbid(unsafe_code)]

mod chainspec;
mod check;
mod hash;
mod ids;
mod maps;
mod merkle;
pub mod protocol;
mod types;
pub mod work;

pub use chainspec::{
    Allocation, ChainSpec, ConsensusParams, GenesisHeader, NetworkName, SpecError, check_genesis,
    genesis_block, genesis_id, parse_chain_spec,
};
pub use check::{TxError, verify_proof_tx, verify_proof_tx_with, verify_tx, verify_tx_with};
pub use hash::{
    block_id, encoded_len, eta_chain, mask, proof_tx_hash, sign_body, signing_bytes,
    signing_bytes_into, txid,
};
pub use ids::{BlockId, CircuitId, ProofHash, TxId};
pub use maps::{BlockIdHasher, BlockMap, FastMap, FastState};
pub use merkle::{
    InclusionPath, MerkleError, bound_root, inclusion_proof, leaf_count_u32, merkle_root,
    verify_inclusion,
};
pub use types::{
    Account, Amount, Block, BlockHeader, ChainId, CircuitEntry, ConstraintCount, HeaderError,
    Height, Nonce, PowNonce, ProofSystem, ProofTx, SignedTx, SystemId, Timestamp, TxBody, TxKind,
    UsageCounter,
};
pub use work::{CumWork, Target, U256, Work, block_work};

pub use pouw_crypto as crypto;
pub use zerocopy::little_endian::{U32, U64};

#[cfg(test)]
mod tests;
