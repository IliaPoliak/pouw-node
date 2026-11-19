//! Events of `contracts/node-events.md`, served by `GET /v1/events`.

use std::{collections::BTreeMap, fmt, str::FromStr};

use pouw_crypto::{Address, FieldInput};
use pouw_types::{Amount, BlockId, ChainId, CircuitId, Height, ProofHash, ProofSystem, TxId};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use thiserror::Error;
use time::{OffsetDateTime, UtcOffset, format_description::FormatItem, macros::format_description};

/// Events per answer when the request gives no `limit`.
pub const DEFAULT_LIMIT: u32 = 100;
/// Largest `limit`; a larger value is lowered to it.
pub const MAX_LIMIT: u32 = 1000;
/// Largest `wait_ms`; a larger value is lowered to it.
pub const MAX_WAIT_MS: u64 = 30_000;
/// The node keeps at least this many events, or the last 24 hours, whichever is more.
pub const EVENT_RETENTION: u64 = 100_000;

/// One event with its envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Starts at 1 and grows by 1 per node, with no gaps.
    pub seq: u64,
    /// By the clock of the node.
    pub time: EventTime,
    /// The node that observed the event.
    pub node_id: NodeId,
    /// `kind` and `data`.
    #[serde(flatten)]
    pub kind: EventKind,
}

/// Answer of `GET /v1/events`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsPage {
    /// Ascending `seq`.
    pub events: Vec<Event>,
    /// `seq` of the last event, or the request's `after` when `events` is empty.
    pub next: u64,
}

/// The kinds of node-events.md with their `data`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventKind {
    TxReceived(TxReceived),
    TxRejected(TxRejected),
    /// This miner began proving a request.
    ProofRequestStarted(ProofRequestStarted),
    /// This miner finished a proof.
    ProofProduced(ProofProduced),
    /// The outcome of the lottery for one proof this miner made: it stayed in the chain
    /// (`won`) or it did not.
    LotteryResult(LotteryResult),
    /// A block arrived from a peer, before verification.
    BlockReceived(BlockReceived),
    BlockVerified(BlockVerified),
    BlockAccepted(BlockAccepted),
    BlockRejected(BlockRejected),
    /// Fork choice moved away from an accepted block.
    BlockOrphaned(BlockOrphaned),
    /// One proof tx was checked during block verification.
    ProofVerified(ProofVerified),
    /// Periodic mempool summary.
    MempoolSnapshot(MempoolSnapshot),
    PeerConnected(Peer),
    PeerDisconnected(Peer),
    /// The process started; the first event after every start.
    NodeStarted(NodeStarted),
}

impl EventKind {
    /// The `kind` string of the envelope.
    pub fn name(&self) -> &'static str {
        match self {
            EventKind::TxReceived(_) => "tx_received",
            EventKind::TxRejected(_) => "tx_rejected",
            EventKind::ProofRequestStarted(_) => "proof_request_started",
            EventKind::ProofProduced(_) => "proof_produced",
            EventKind::LotteryResult(_) => "lottery_result",
            EventKind::BlockReceived(_) => "block_received",
            EventKind::BlockVerified(_) => "block_verified",
            EventKind::BlockAccepted(_) => "block_accepted",
            EventKind::BlockRejected(_) => "block_rejected",
            EventKind::BlockOrphaned(_) => "block_orphaned",
            EventKind::ProofVerified(_) => "proof_verified",
            EventKind::MempoolSnapshot(_) => "mempool_snapshot",
            EventKind::PeerConnected(_) => "peer_connected",
            EventKind::PeerDisconnected(_) => "peer_disconnected",
            EventKind::NodeStarted(_) => "node_started",
        }
    }
}

/// Data of [`EventKind::TxReceived`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxReceived {
    pub txid: TxId,
    /// `transfer`, `proof_request` or `register_circuit`.
    pub tx_kind: String,
    pub sender: Address,
    pub fee: Amount,
}

/// Data of [`EventKind::TxRejected`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxRejected {
    /// Absent when the bytes did not parse.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub txid: Option<TxId>,
    /// Lowercase `snake_case` reason.
    pub reason_code: String,
    /// For people.
    pub message: String,
}

/// Data of [`EventKind::ProofRequestStarted`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRequestStarted {
    pub txid: TxId,
    pub circuit: CircuitId,
    pub system: ProofSystem,
}

/// Data of [`EventKind::ProofProduced`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofProduced {
    pub txid: TxId,
    pub circuit: CircuitId,
    pub system: ProofSystem,
    /// Wall time of proving by this node.
    pub prove_ms: u64,
    pub proof_hash: ProofHash,
}

/// Data of [`EventKind::LotteryResult`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LotteryResult {
    /// The proof request.
    pub txid: TxId,
    pub proof_hash: ProofHash,
    pub circuit: CircuitId,
    /// The block with this proof is in the chain of the node. A proof that won can still
    /// lose later: a reorganization that drops the block is a second event of the same
    /// `proof_hash` with `won: false` and the reason `orphaned`.
    pub won: bool,
    /// Why the proof lost, absent when it won: `superseded` (the tip moved to a block of
    /// another miner before ours was found), `request_gone` (the request left the
    /// mempool before a block took the proof) or `orphaned` (our block was dropped by a
    /// reorganization).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub eta: FieldInput,
    pub mask: FieldInput,
    pub usage_counter: u64,
}

/// Data of [`EventKind::BlockReceived`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockReceived {
    pub id: BlockId,
    pub height: Height,
    pub from_peer: String,
}

/// Data of [`EventKind::BlockVerified`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockVerified {
    pub id: BlockId,
    pub height: Height,
    /// Wall time of the whole verification.
    pub verify_ms: u64,
    pub proof_count: u64,
    pub ok: bool,
}

/// Data of [`EventKind::BlockAccepted`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockAccepted {
    pub id: BlockId,
    pub height: Height,
    /// `header.miner`.
    pub miner: Address,
    /// Entries of `txs`.
    pub tx_count: u64,
    /// Entries of `proof_txs`.
    pub proof_count: u64,
}

/// Data of [`EventKind::BlockRejected`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockRejected {
    pub id: BlockId,
    /// Absent when the header could not be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<Height>,
    /// Lowercase `snake_case` reason.
    pub reason_code: String,
}

/// Data of [`EventKind::BlockOrphaned`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockOrphaned {
    pub id: BlockId,
    pub height: Height,
}

/// Data of [`EventKind::ProofVerified`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofVerified {
    pub txid: TxId,
    pub proof_hash: ProofHash,
    pub system: ProofSystem,
    /// Wall time of this verification.
    pub verify_ms: u64,
    pub ok: bool,
}

/// Data of [`EventKind::MempoolSnapshot`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MempoolSnapshot {
    pub pending_txs: u64,
    pub pending_proof_requests: u64,
    /// Pending proof requests per circuit.
    pub by_circuit: BTreeMap<CircuitId, u64>,
}

/// Data of [`EventKind::PeerConnected`] and [`EventKind::PeerDisconnected`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub peer_id: String,
}

/// Data of [`EventKind::NodeStarted`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeStarted {
    /// Chain id of genesis.
    pub chain_id: ChainId,
    pub version: String,
    pub height: Height,
}

/// Name of a node in the events, 1 to 64 characters of `[A-Za-z0-9._-]`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(String);

/// Why a string is not a [`NodeId`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("a node id has 1 to 64 characters of [A-Za-z0-9._-], found {0:?}")]
pub struct BadNodeId(pub String);

impl Default for NodeId {
    /// `node`.
    fn default() -> Self {
        Self("node".to_owned())
    }
}

impl NodeId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for NodeId {
    type Err = BadNodeId;

    fn from_str(s: &str) -> Result<Self, BadNodeId> {
        let allowed = |c: char| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-');
        if (1..=64).contains(&s.len()) && s.chars().all(allowed) {
            Ok(Self(s.to_owned()))
        } else {
            Err(BadNodeId(s.to_owned()))
        }
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for NodeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

const EVENT_TIME_FORMAT: &[FormatItem<'static>] =
    format_description!("[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z");

/// RFC 3339 UTC with milliseconds, `2026-10-19T14:03:22.417Z`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventTime(OffsetDateTime);

impl EventTime {
    /// The current time of this machine.
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }

    /// Milliseconds since the Unix epoch, `None` when out of range.
    pub fn from_unix_millis(millis: i64) -> Option<Self> {
        let nanos = i128::from(millis).checked_mul(1_000_000)?;
        OffsetDateTime::from_unix_timestamp_nanos(nanos)
            .ok()
            .map(Self)
    }
}

impl fmt::Display for EventTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[expect(
            clippy::map_err_ignore,
            reason = "fmt::Error carries no detail, so the source has nowhere to go"
        )]
        let text = self
            .0
            .to_offset(UtcOffset::UTC)
            .format(EVENT_TIME_FORMAT)
            .map_err(|_| fmt::Error)?;
        f.write_str(&text)
    }
}

impl FromStr for EventTime {
    type Err = time::error::Parse;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        time::PrimitiveDateTime::parse(s, EVENT_TIME_FORMAT).map(|t| Self(t.assume_utc()))
    }
}

impl Serialize for EventTime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EventTime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}
