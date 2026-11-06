//! Node configuration from `POUW_*` environment variables. Every variable has a
//! default, so an empty environment gives a single in-memory node with a mock prover.
//! An unknown `POUW_*` variable is an error, so a typo does not go unnoticed.

use std::{
    io,
    net::{AddrParseError, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::ParseIntError,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use pouw_api::event::{BadNodeId, NodeId};
use pouw_crypto::{Address, ParseError};
use pouw_types::{Block, ChainSpec, SpecError, check_genesis, parse_chain_spec};
use thiserror::Error;

use crate::{mempool::MempoolLimits, p2p::PeerLimits};

/// Variable names and their defaults.
pub mod var {
    /// Name of the node in its events. Default `node`.
    pub const NODE_ID: &str = "POUW_NODE_ID";
    /// Path of the chain spec JSON, see `docs/CHAINSPEC.md`. Default the builtin devnet
    /// spec.
    pub const CHAIN_SPEC: &str = "POUW_CHAIN_SPEC";
    /// Address of the REST API and `/health`. Default `[::]:8000`, both IP families.
    pub const API_ADDR: &str = "POUW_API_ADDR";
    /// Address of `/metrics`. Default `[::]:9100`, both IP families.
    pub const METRICS_ADDR: &str = "POUW_METRICS_ADDR";
    /// Folder with the `chain.json` of `contracts/fixtures`. When set, the API answers
    /// from it as a mock node (pouw-node#59). Default unset.
    pub const API_FIXTURES: &str = "POUW_API_FIXTURES";
    /// Directory of the database and the node key. Default `data`.
    pub const DATA_DIR: &str = "POUW_DATA_DIR";
    /// `memory` or `rocksdb`. Default `memory`.
    pub const STORE: &str = "POUW_STORE";
    /// `mock` or `groth16`. Default `mock`.
    pub const PROVER: &str = "POUW_PROVER";
    /// Proving time of the mock prover in milliseconds. Default `0`.
    pub const MOCK_PROVE_DELAY_MS: &str = "POUW_MOCK_PROVE_DELAY_MS";
    /// Comma-separated listen addresses of the peer-to-peer transport. Default
    /// `/ip6/::/tcp/30333,/ip4/0.0.0.0/tcp/30333`.
    pub const P2P_LISTEN: &str = "POUW_P2P_LISTEN";
    /// Comma-separated addresses of the peers to dial at start. Default empty.
    pub const BOOTNODES: &str = "POUW_BOOTNODES";
    /// Most connections the node dials. Default `8`.
    pub const MAX_OUTBOUND: &str = "POUW_MAX_OUTBOUND";
    /// Most connections the node accepts. Default `32`.
    pub const MAX_INBOUND: &str = "POUW_MAX_INBOUND";
    /// Gossipsub mesh degree D. Default `6`.
    pub const MESH_D: &str = "POUW_MESH_D";
    /// Entries of one Kademlia k-bucket. Default `20`.
    pub const KADEMLIA_BUCKET_SIZE: &str = "POUW_KADEMLIA_BUCKET_SIZE";
    /// `addr:` of the miner's reward; the node mines only when it is set.
    pub const MINER_ADDRESS: &str = "POUW_MINER_ADDRESS";
    /// Most borsh bytes the mempool holds. Default `67108864` (64 MiB).
    pub const MEMPOOL_BYTES: &str = "POUW_MEMPOOL_BYTES";
    /// Most pending transactions of one sender. Default `16`.
    pub const MEMPOOL_SENDER_SLOTS: &str = "POUW_MEMPOOL_SENDER_SLOTS";
}

/// What is wrong with the value of a variable.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum Reason {
    #[error("{0}")]
    Expected(&'static str),
    #[error("not a number: {0}")]
    Number(#[from] ParseIntError),
    #[error("not a socket address: {0}")]
    Socket(#[from] AddrParseError),
    #[error("bad ip4 address: {0}")]
    Ip4(#[source] AddrParseError),
    #[error("bad ip6 address: {0}")]
    Ip6(#[source] AddrParseError),
    #[error(transparent)]
    NodeId(#[from] BadNodeId),
    #[error("not an address: {0}")]
    Address(#[from] ParseError),
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum ConfigError {
    /// A variable has a value the node cannot use.
    #[error("{var}={value:?}: {reason}")]
    Invalid {
        var: &'static str,
        value: String,
        /// What is wrong with it.
        #[source]
        reason: Reason,
    },
    /// A `POUW_*` variable the node does not read.
    #[error("unknown variable {0}")]
    Unknown(String),
}

/// The storage engine to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreKind {
    /// Everything in memory, lost at exit.
    Memory,
    /// The `RocksDB` database under the data directory.
    Rocksdb,
}

impl StoreKind {
    /// The cargo feature of `pouw-node` that builds this engine.
    pub const fn feature(self) -> &'static str {
        match self {
            Self::Memory => "store-mem",
            Self::Rocksdb => "rocksdb",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProverKind {
    /// [`pouw_provers::MockProver`] with this proving time.
    Mock {
        /// Simulated proving time.
        delay: Duration,
    },
    /// Groth16 over BN254.
    Groth16,
}

/// The configuration of one node process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub node_id: NodeId,
    /// The chain spec file, or the builtin devnet spec when absent.
    pub chain_spec: Option<PathBuf>,
    pub api_addr: SocketAddr,
    pub metrics_addr: SocketAddr,
    /// Folder of the fixture chain the API serves instead of the node, if any.
    pub api_fixtures: Option<PathBuf>,
    pub data_dir: PathBuf,
    pub store: StoreKind,
    pub prover: ProverKind,
    /// Listen multiaddrs of the peer-to-peer transport.
    pub p2p_listen: Vec<String>,
    /// Multiaddrs of the peers to dial at start.
    pub bootnodes: Vec<String>,
    /// Connection counts and discovery sizes of the peer-to-peer transport.
    pub limits: PeerLimits,
    /// Receiver of the rewards; the node mines only when set.
    pub miner: Option<Address>,
    /// Limits of the mempool.
    pub mempool: MempoolLimits,
}

/// The devnet chain spec compiled into the binary.
pub const DEVNET_SPEC: &str = include_str!("../../chainspec/devnet.json");

/// Why the chain spec cannot be loaded.
#[derive(Debug, Error)]
pub enum SpecLoadError {
    /// The file cannot be read.
    #[error("cannot read chain spec {path}: {source}")]
    Read {
        /// The value of `POUW_CHAIN_SPEC`.
        path: PathBuf,
        /// The cause.
        source: io::Error,
    },
    /// The content is not a usable spec, or its genesis id differs from the expected one.
    #[error(transparent)]
    Spec(#[from] SpecError),
}

/// Loads the spec at `path`, or the builtin devnet spec, and builds its genesis block.
/// Fails when the genesis id differs from `expected_genesis_id`.
pub fn load_chain(path: Option<&Path>) -> Result<(ChainSpec, Block), SpecLoadError> {
    let spec = match path {
        Some(path) => {
            let json = std::fs::read_to_string(path).map_err(|source| SpecLoadError::Read {
                path: path.to_owned(),
                source,
            })?;
            parse_chain_spec(&json)?
        }
        None => parse_chain_spec(DEVNET_SPEC)?,
    };
    let genesis = check_genesis(&spec)?;
    Ok((spec, genesis))
}

fn parse<T: FromStr>(var: &'static str, value: &str) -> Result<T, ConfigError>
where
    Reason: From<T::Err>,
{
    value.parse().map_err(|error: T::Err| ConfigError::Invalid {
        var,
        value: value.to_owned(),
        reason: error.into(),
    })
}

impl NodeConfig {
    /// Reads the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_vars(std::env::vars())
    }

    /// Reads the given variables; the others are ignored unless they start with `POUW_`.
    pub fn from_vars(
        vars: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let mut config = Self::default();
        let mut mock_delay = Duration::ZERO;
        let mut groth16 = false;
        for (name, value) in vars {
            match name.as_str() {
                var::NODE_ID => config.node_id = parse(var::NODE_ID, &value)?,
                var::CHAIN_SPEC => config.chain_spec = Some(PathBuf::from(value)),
                var::API_ADDR => config.api_addr = parse(var::API_ADDR, &value)?,
                var::METRICS_ADDR => config.metrics_addr = parse(var::METRICS_ADDR, &value)?,
                var::API_FIXTURES => config.api_fixtures = Some(PathBuf::from(value)),
                var::DATA_DIR => config.data_dir = PathBuf::from(value),
                var::STORE => {
                    config.store = match value.as_str() {
                        "memory" => StoreKind::Memory,
                        "rocksdb" => StoreKind::Rocksdb,
                        _ => {
                            return Err(invalid(
                                var::STORE,
                                value,
                                Reason::Expected("expected memory or rocksdb"),
                            ));
                        }
                    }
                }
                var::PROVER => {
                    groth16 = match value.as_str() {
                        "mock" => false,
                        "groth16" => true,
                        _ => {
                            return Err(invalid(
                                var::PROVER,
                                value,
                                Reason::Expected("expected mock or groth16"),
                            ));
                        }
                    }
                }
                var::MOCK_PROVE_DELAY_MS => {
                    mock_delay = Duration::from_millis(parse(var::MOCK_PROVE_DELAY_MS, &value)?);
                }
                var::P2P_LISTEN => config.p2p_listen = multiaddrs(var::P2P_LISTEN, &value)?,
                var::BOOTNODES => config.bootnodes = multiaddrs(var::BOOTNODES, &value)?,
                var::MAX_OUTBOUND => config.limits.max_outbound = parse(var::MAX_OUTBOUND, &value)?,
                var::MAX_INBOUND => config.limits.max_inbound = parse(var::MAX_INBOUND, &value)?,
                var::MESH_D => config.limits.mesh_d = parse(var::MESH_D, &value)?,
                var::KADEMLIA_BUCKET_SIZE => {
                    config.limits.kademlia_bucket_size = parse(var::KADEMLIA_BUCKET_SIZE, &value)?;
                }
                var::MINER_ADDRESS => config.miner = Some(parse(var::MINER_ADDRESS, &value)?),
                var::MEMPOOL_BYTES => {
                    config.mempool.max_bytes = parse(var::MEMPOOL_BYTES, &value)?;
                }
                var::MEMPOOL_SENDER_SLOTS => {
                    config.mempool.sender_slots = parse(var::MEMPOOL_SENDER_SLOTS, &value)?;
                }
                other if other.starts_with("POUW_") => {
                    return Err(ConfigError::Unknown(other.to_owned()));
                }
                _ => {}
            }
        }
        config.prover = if groth16 {
            ProverKind::Groth16
        } else {
            ProverKind::Mock { delay: mock_delay }
        };
        Ok(config)
    }
}

fn multiaddrs(var: &'static str, list: &str) -> Result<Vec<String>, ConfigError> {
    list.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|addr| match check_multiaddr(addr) {
            Ok(()) => Ok(addr.to_owned()),
            Err(reason) => Err(invalid(var, addr.to_owned(), reason)),
        })
        .collect()
}

/// Accepts `/<ip4|ip6|dns|dns4|dns6>/<host>/tcp/<port>` with an optional `/p2p/<id>`.
fn check_multiaddr(addr: &str) -> Result<(), Reason> {
    let mut parts = addr
        .strip_prefix('/')
        .ok_or(Reason::Expected("expected a multiaddr"))?
        .split('/');
    let (Some(proto), Some(host)) = (parts.next(), parts.next()) else {
        return Err(Reason::Expected("expected a host"));
    };
    match proto {
        "ip4" => drop(host.parse::<Ipv4Addr>().map_err(Reason::Ip4)?),
        "ip6" => drop(host.parse::<Ipv6Addr>().map_err(Reason::Ip6)?),
        "dns" | "dns4" | "dns6" if !host.is_empty() => {}
        "dns" | "dns4" | "dns6" => return Err(Reason::Expected("empty host name")),
        _ => {
            return Err(Reason::Expected("expected ip4, ip6, dns, dns4 or dns6"));
        }
    }
    if parts.next() != Some("tcp") {
        return Err(Reason::Expected("expected tcp"));
    }
    let port = parts
        .next()
        .ok_or(Reason::Expected("expected a tcp port"))?;
    port.parse::<u16>()?;
    match (parts.next(), parts.next(), parts.next()) {
        (None, ..) => Ok(()),
        (Some("p2p"), Some(id), None) if !id.is_empty() => Ok(()),
        _ => Err(Reason::Expected(
            "expected nothing or /p2p/<id> after the port",
        )),
    }
}

fn invalid(var: &'static str, value: String, reason: Reason) -> ConfigError {
    ConfigError::Invalid { var, value, reason }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: NodeId::default(),
            chain_spec: None,
            api_addr: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 8000)),
            metrics_addr: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 9100)),
            api_fixtures: None,
            data_dir: PathBuf::from("data"),
            store: StoreKind::Memory,
            prover: ProverKind::Mock {
                delay: Duration::ZERO,
            },
            p2p_listen: vec![
                "/ip6/::/tcp/30333".to_owned(),
                "/ip4/0.0.0.0/tcp/30333".to_owned(),
            ],
            bootnodes: Vec::new(),
            limits: PeerLimits::default(),
            miner: None,
            mempool: MempoolLimits {
                max_bytes: 64 << 20,
                sender_slots: 16,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use pouw_types::{BlockId, block_id};

    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn defaults_match_the_deployment() {
        let config = NodeConfig::from_vars(vars(&[("HOME", "/root")])).unwrap();
        assert_eq!(config.api_addr.port(), 8000);
        assert_eq!(config.metrics_addr.port(), 9100);
        assert_eq!(config.store, StoreKind::Memory);
        assert_eq!(config.limits, PeerLimits::default());
        assert_eq!(
            config.prover,
            ProverKind::Mock {
                delay: Duration::ZERO
            }
        );
    }

    #[test]
    fn every_variable_is_read() {
        let address = format!("addr:{}", "11".repeat(32));
        let config = NodeConfig::from_vars(vars(&[
            (var::NODE_ID, "miner-1"),
            (var::CHAIN_SPEC, "/etc/pouw/chain.json"),
            (var::API_ADDR, "127.0.0.1:18000"),
            (var::METRICS_ADDR, "127.0.0.1:19100"),
            (var::DATA_DIR, "/var/lib/pouw"),
            (var::STORE, "rocksdb"),
            (var::MOCK_PROVE_DELAY_MS, "250"),
            (var::P2P_LISTEN, "/ip4/0.0.0.0/tcp/4001"),
            (
                var::BOOTNODES,
                "/dns4/node-1/tcp/4001, /dns4/node-2/tcp/4001",
            ),
            (var::MINER_ADDRESS, &address),
            (var::MEMPOOL_BYTES, "5000"),
            (var::MEMPOOL_SENDER_SLOTS, "5"),
            (var::MAX_OUTBOUND, "4"),
            (var::MAX_INBOUND, "16"),
            (var::MESH_D, "5"),
            (var::KADEMLIA_BUCKET_SIZE, "10"),
        ]))
        .unwrap();
        assert_eq!(config.node_id.as_str(), "miner-1");
        assert_eq!(
            config.chain_spec,
            Some(PathBuf::from("/etc/pouw/chain.json"))
        );
        assert_eq!(
            config.prover,
            ProverKind::Mock {
                delay: Duration::from_millis(250)
            }
        );
        assert_eq!(config.store, StoreKind::Rocksdb);
        assert_eq!(config.bootnodes.len(), 2);
        assert_eq!(config.miner, Some(Address([0x11; 32])));
        assert_eq!(
            config.mempool,
            MempoolLimits {
                max_bytes: 5000,
                sender_slots: 5
            }
        );
        assert_eq!(
            config.limits,
            PeerLimits {
                max_outbound: 4,
                max_inbound: 16,
                mesh_d: 5,
                kademlia_bucket_size: 10
            }
        );
        let groth16 = NodeConfig::from_vars(vars(&[(var::PROVER, "groth16")])).unwrap();
        assert_eq!(groth16.prover, ProverKind::Groth16);
    }

    #[test]
    fn the_builtin_devnet_spec_is_the_default() {
        assert_eq!(NodeConfig::default().chain_spec, None);
        let (spec, genesis) = load_chain(None).unwrap();
        assert_eq!(spec.network.as_str(), "devnet");
        assert_eq!(block_id(&genesis.header), spec.expected_genesis_id);
    }

    #[test]
    fn a_spec_file_with_a_wrong_genesis_id_is_refused() {
        let dir = std::env::temp_dir().join(format!("pouw-spec-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wrong.json");
        let (spec, _) = load_chain(None).unwrap();
        let wrong = DEVNET_SPEC.replace(
            &spec.expected_genesis_id.to_string(),
            &BlockId::ZERO.to_string(),
        );
        assert_ne!(wrong, DEVNET_SPEC);
        std::fs::write(&path, wrong).unwrap();
        let error = load_chain(Some(&path)).unwrap_err();
        assert!(matches!(
            error,
            SpecLoadError::Spec(SpecError::GenesisMismatch { .. })
        ));
        let missing = load_chain(Some(&dir.join("missing.json"))).unwrap_err();
        assert!(matches!(missing, SpecLoadError::Read { .. }));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn listens_on_both_families_by_default() {
        let config = NodeConfig::default();
        assert_eq!(config.api_addr, "[::]:8000".parse().unwrap());
        assert_eq!(config.metrics_addr, "[::]:9100".parse().unwrap());
        assert_eq!(
            config.p2p_listen,
            ["/ip6/::/tcp/30333", "/ip4/0.0.0.0/tcp/30333"]
        );
    }

    #[test]
    fn ipv6_addresses_are_accepted() {
        let config = NodeConfig::from_vars(vars(&[
            (var::API_ADDR, "[::1]:18000"),
            (
                var::P2P_LISTEN,
                "/ip6/::1/tcp/4001, /ip4/127.0.0.1/tcp/4001",
            ),
            (
                var::BOOTNODES,
                "/ip6/2001:db8::1/tcp/4001,/dns6/node-1/tcp/4001,/dns/node-2/tcp/4001/p2p/12D3KooW",
            ),
        ]))
        .unwrap();
        assert_eq!(config.api_addr, "[::1]:18000".parse().unwrap());
        assert_eq!(config.p2p_listen.len(), 2);
        assert_eq!(config.bootnodes.len(), 3);
    }

    #[test]
    fn bad_peer_addresses_are_errors() {
        for bad in [
            "/ip6/127.0.0.1/tcp/1",
            "/ip4/::1/tcp/1",
            "/ip6/::1",
            "/ip6/::1/tcp/x",
            "/dns6//tcp/1",
            "/udp/1",
            "[::1]:4001",
            "/ip6/::1/tcp/1/p2p",
        ] {
            assert!(
                NodeConfig::from_vars(vars(&[(var::BOOTNODES, bad)])).is_err(),
                "{bad}"
            );
            assert!(
                NodeConfig::from_vars(vars(&[(var::P2P_LISTEN, bad)])).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn bad_and_unknown_variables_are_errors() {
        assert_eq!(
            NodeConfig::from_vars(vars(&[("POUW_CHAIN_ID", "1")])),
            Err(ConfigError::Unknown("POUW_CHAIN_ID".to_owned()))
        );
        assert!(NodeConfig::from_vars(vars(&[(var::NODE_ID, "a b")])).is_err());
        assert!(NodeConfig::from_vars(vars(&[(var::PROVER, "plonk")])).is_err());
        assert!(NodeConfig::from_vars(vars(&[(var::STORE, "sled")])).is_err());
        assert_eq!(
            NodeConfig::from_vars(vars(&[("POUW_CHAINID", "1")])),
            Err(ConfigError::Unknown("POUW_CHAINID".to_owned()))
        );
    }
}
