//! The light node: a small process that follows the chain through full nodes, keeps
//! headers only and will answer the light API of `contracts/light-node-api.md`. It
//! stores no chain and verifies no proof.
//!
//! This is the skeleton of pouw-node#101: the configuration from `POUW_*` variables and
//! `/health`. The header sync and the light API come with pouw-node#102.

pub mod config;
pub mod health;
