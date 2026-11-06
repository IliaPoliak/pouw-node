//! The PoUW-ZK full node: everything around consensus that a running process needs.
//! Consensus rules are in `pouw_consensus`, proving backends behind
//! `pouw_provers::Prover`, and the API types in `pouw_api`; this crate wires them
//! to storage, the mempool, the network, the event log and the metrics. The loop that
//! owns all of it is [`node::run`].

#![forbid(unsafe_code)]

pub mod api;
pub mod chain;
pub mod config;
pub mod events;
pub mod http;
pub mod mempool;
pub mod metrics;
pub mod miner;
pub mod node;
pub mod p2p;
pub mod precheck;
pub mod signals;
pub mod store;
pub mod sync;
