//! The light node: a small process that follows the chain through full nodes, keeps
//! headers only and will answer the light API of `contracts/light-node-api.md`. It
//! stores no chain and verifies no proof.
//!
//! Parts so far: the configuration from `POUW_*` variables and `/health`
//! (pouw-node#101), the header store (pouw-node#102), the verification of a header
//! against the stored chain and the header routes of the light API (pouw-node#103).
//! The routes a full node answers (block, account, tx, inclusion proof, proof job)
//! are forwarded to `POUW_FULL_NODES` (pouw-node#103). The header sync of
//! pouw-node#104 follows the chain of the chain spec through the same nodes.

pub mod api;
pub mod config;
pub mod headers;
pub mod health;
pub mod sync;
pub mod upstream;
pub mod verify;
