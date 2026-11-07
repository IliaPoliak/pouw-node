# pouw-node

Reference node of PoUW-ZK. It is a Bitcoin-shaped account-model proof-of-work L1: miners
find blocks by hashing a 168-byte header, and a block carries a Groth16 proof that a
client paid a fee to request. One Cargo workspace holds the node, the shared types and
the client libraries (Rust stable, edition 2024).

The formats are fixed by the contracts in [pouw-docs]. The code follows them, and a
change to a format starts as a pull request there.

## Running one mining node

Make an address with the CLI, then start the node with the devnet spec and that address.

```sh
cargo run -p pouw-cli -- keygen
POUW_MINER_ADDRESS=addr:<64 hex from keygen> cargo run -p pouw-node
```

Without `POUW_CHAIN_SPEC` the node uses `chainspec/devnet.json`, see
`docs/CHAINSPEC.md`. Without a miner address it does not mine. The node stops on SIGINT
or SIGTERM with exit code 0, a fault of the node loop is 3, an invalid configuration 2
and a node that cannot start 1. A component that is not implemented yet logs a warning
with its issue number, see `docs/FOR-ILIA.md`.

Default features are all features. A slim binary names the ones it wants:
`cargo build -p pouw-node --no-default-features --features store-mem`.

## Docker and the whole network

`Dockerfile` builds the image that pouw-deploy runs as `node-1`
(`ghcr.io/pouw-zk/pouw-node`, published from `main` by `docker.yml`). The node in it
keeps its key in `/data` and takes the same `POUW_*` variables. To run the whole network
with your local changes, clone pouw-deploy next to this repository and run `make dev`
there.

## Environment

The node reads `POUW_*` variables, an unknown one is an error. `RUST_LOG` filters the
log, `info` by default.

| variable | default | meaning |
| --- | --- | --- |
| `POUW_NODE_ID` | `node` | name of the node in its events |
| `POUW_CHAIN_SPEC` | builtin devnet spec | path of the chain spec JSON |
| `POUW_API_ADDR` | `[::]:8000` | REST API and `/health` |
| `POUW_METRICS_ADDR` | `[::]:9100` | `/metrics` |
| `POUW_DATA_DIR` | `data` | database and node key |
| `POUW_STORE` | `memory` | `memory` or `rocksdb` |
| `POUW_PROVER` | `mock` | `mock` or `groth16` |
| `POUW_MOCK_PROVE_DELAY_MS` | `0` | proving time of the mock prover |
| `POUW_P2P_LISTEN` | `/ip6/::/tcp/30333,/ip4/0.0.0.0/tcp/30333` | comma-separated listen multiaddrs |
| `POUW_BOOTNODES` | empty | comma-separated multiaddrs of the peers to dial |
| `POUW_MAX_OUTBOUND` | `8` | most connections the node dials |
| `POUW_MAX_INBOUND` | `32` | most connections the node accepts |
| `POUW_MESH_D` | `6` | gossipsub mesh degree |
| `POUW_KADEMLIA_BUCKET_SIZE` | `20` | entries of one Kademlia k-bucket |
| `POUW_MINER_ADDRESS` | unset | `addr:` of the reward, the node mines only when set |
| `POUW_MEMPOOL_BYTES` | `67108864` | most borsh bytes of all pending transactions |
| `POUW_MEMPOOL_SENDER_SLOTS` | `16` | most pending transactions of one sender |

Addresses of the API and metrics are `ip:port`, IPv6 in brackets. P2P and bootnode
addresses are multiaddrs `/<ip4|ip6|dns|dns4|dns6>/<host>/tcp/<port>`, optionally
followed by `/p2p/<id>`. The node does not set `IPV6_V6ONLY`: a bind to `[::]` serves
IPv4 too only while `net.ipv6.bindv6only=0`, the Linux default.

## Crates

A crate depends only on crates above it in this list.

| crate | role |
| --- | --- |
| `pouw-crypto` | `Hash32`, `Address`, `Signature`, SHA-256, Ed25519 |
| `pouw-types` | transactions, blocks, ids, protocol constants, chain spec, hash rules |
| `pouw-provers` | `Prover` enum, `MockProver`, Groth16 behind the `groth16` feature |
| `pouw-consensus` | chain state and diffs, validity rules, `pow`, `difficulty`, `timestamp`, `fork_choice`, `reward` |
| `pouw-api` | JSON views, error body, paths, events, `NodeClient` |
| `pouw-light-client` | wallet: keys, nonces, signed transactions |
| `pouw-light-node` | light node: `/health` and its configuration, header sync follows in #102 |
| `pouw-node` | node loop, store, mempool, event log, P2P boundary, miner |
| `pouw-cli` | bin `pouw`: keys, signed transfers, txids, genesis id |

`pouw-crypto`, `pouw-types`, `pouw-api` and `pouw-light-client` never depend on
`pouw-node`, `pouw-consensus` or the prover crate. CI enforces it:

```sh
cargo build --locked -p pouw-light-client
! cargo tree --locked -p pouw-light-client -e normal --prefix none --format '{lib}' | grep -E '^pouw_(node|prover|consensus)'
```

## Gate

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
cargo deny check
```

## Layout

- `crates/` the workspace members above.
- `chainspec/` the devnet chain spec.
- `circuits/` Circom sources of the task catalog, see [circuits/README.md](circuits/README.md).
- `e2e/` end-to-end tests against a running network, see [e2e/README.md](e2e/README.md).
- `docs/CHAINSPEC.md` the chain spec fields and the devnet values.
- `docs/FOR-ILIA.md` the map of stages, stubs and ABIs.

Rules for contributors are in [CONTRIBUTING.md](CONTRIBUTING.md).

[pouw-docs]: https://github.com/PoUW-ZK/pouw-docs/tree/main/contracts
