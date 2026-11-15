//! The boundary between the node and its peer-to-peer transport: the messages, the
//! topics and the two directions of calls. The transport (libp2p gossipsub and
//! request-response) owns the receiving end of a [`Network`] handle and sends the node
//! [`Inbound`] messages. Messages are borsh, like everything else on the wire.
//!
//! The transport thread owns [`Transport`]: the table of connected peers, their
//! scores and the counters that number gossip messages and served requests. The node
//! never sees a [`PeerId`]: it names a peer by the [`PeerIx`] the transport assigned on
//! connect, and every [`Command`] about a peer carries that index.
//!
//! ```text
//!  swarm (pouw-node#85) -- Wire (WIRE_CAPACITY) --> transport thread
//!                                                    |  decode, number, map PeerId to PeerIx
//!                                                    v
//!                          node loop <-- Inbound (P2P_CAPACITY, `send().await`)
//!                          node loop --> Command (COMMAND_CAPACITY, try_send) --> transport
//! ```
//!
//! Backpressure: the transport awaits a free slot of the p2p channel before it reads
//! the next [`Wire`] message, so a slow node slows the reads of the swarm (the libp2p
//! swarm of pouw-node#85 stops polling its sockets while that await is pending). The
//! node never awaits the transport: a full command channel drops the command and counts
//! it in `Metrics::dropped_commands`.

use std::{collections::BTreeMap, fmt, future::poll_fn, io, path::PathBuf, task::Poll};

use borsh::BorshSerialize;
use pouw_consensus::{ConsensusParams, Scratch};
use pouw_crypto::text::Hex;
use pouw_types::{BlockHeader, NetworkName, TxKind};
use thiserror::Error;
use tokio::{runtime, sync::mpsc};
use tracing::{debug, info, warn};

use crate::{
    metrics::Metrics,
    node::ComponentFault,
    precheck::{self, CheckedAnnounce, CheckedTx, Fetched, PrecheckError},
};

pub mod identity;
pub mod limits;
pub mod protocol;
pub mod swarm;

pub use limits::{
    BAN_DURATION, BAN_SCORE, MAX_PEER_ID_BYTES, PENALTY_INVALID_BLOCK, PENALTY_INVALID_TX,
    PENALTY_MALFORMED, PENALTY_UNRESPONSIVE, PeerLimits, WIRE_CAPACITY,
};
pub use protocol::{DisconnectReason, GetBlocks, GetHeaders, Status, SyncRequest, SyncResponse};

/// The bytes of a peer id are longer than [`MAX_PEER_ID_BYTES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("a peer id has at most {MAX_PEER_ID_BYTES} bytes, found {0}")]
pub struct PeerIdTooLong(pub usize);

/// Identity of a peer as the transport names it: its multihash bytes, kept inline.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerId {
    len: u8,
    bytes: [u8; MAX_PEER_ID_BYTES],
}

impl PeerId {
    /// The id with exactly `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PeerIdTooLong> {
        let len = u8::try_from(bytes.len())
            .ok()
            .filter(|len| usize::from(*len) <= MAX_PEER_ID_BYTES)
            .ok_or(PeerIdTooLong(bytes.len()))?;
        let mut inline = [0; MAX_PEER_ID_BYTES];
        inline[..bytes.len()].copy_from_slice(bytes);
        Ok(Self { len, bytes: inline })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", Hex(self.as_bytes()))
    }
}

/// Names a connected peer inside the node. The transport assigns it on connect from a
/// counter that only goes up, so an index never names two peers and a command about a
/// peer that left finds nothing in [`Peers`]. The libp2p [`PeerId`] stays inside this
/// module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeerIx(pub u32);

/// The transport handed out all `u32::MAX` peer indices of this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the peer indices are exhausted")]
pub struct PeerIxExhausted;

/// The connected peers, owned by the transport thread. [`disconnect`] removes the entries
/// of a peer that left, so the tables hold at most `max_inbound + max_outbound` entries.
/// They are `BTreeMap`s: a lookup costs a few comparisons. `PeerId` is chosen by the
/// remote, which rules out a hash map without a keyed hasher. Indices are never reused,
/// so no generation is needed, and a slab would save nothing at this size.
#[derive(Debug, Default)]
pub struct Peers {
    /// The index the next new peer gets.
    pub next: u32,
    pub by_ix: BTreeMap<PeerIx, PeerId>,
    pub by_id: BTreeMap<PeerId, PeerIx>,
}

/// Registers `id` as connected and returns its new index, or `None` when `id` is
/// connected already (a second connection of the same peer is not a new peer).
pub fn connect(peers: &mut Peers, id: PeerId) -> Result<Option<PeerIx>, PeerIxExhausted> {
    if peers.by_id.contains_key(&id) {
        return Ok(None);
    }
    let after = peers.next.checked_add(1).ok_or(PeerIxExhausted)?;
    let ix = PeerIx(peers.next);
    peers.next = after;
    peers.by_ix.insert(ix, id);
    peers.by_id.insert(id, ix);
    Ok(Some(ix))
}

/// Forgets the peer `id` and returns the index it had.
pub fn disconnect(peers: &mut Peers, id: &PeerId) -> Option<PeerIx> {
    let ix = peers.by_id.remove(id)?;
    peers.by_ix.remove(&ix);
    Some(ix)
}

/// A gossip topic. Its protocol id is [`protocol::protocol_id`] of [`Topic::name`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Topic {
    /// Header announcements of new blocks.
    BlockAnnounce,
    /// `Transfer` and `RegisterCircuit` transactions.
    CoinTxs,
    /// Proof requests.
    ProofRequests,
}

impl Topic {
    /// The protocol name of the topic, the `<name>` of `/pouw/<network>/<name>/<version>`.
    pub fn name(self) -> &'static str {
        match self {
            Topic::BlockAnnounce => protocol::BLOCK_ANNOUNCE,
            Topic::CoinTxs => protocol::COIN_TXS,
            Topic::ProofRequests => protocol::PROOF_REQUESTS,
        }
    }

    /// Most bytes of one message on this topic, the `max_transmit_size` the transport
    /// sets for it. The limit is the largest valid message of the topic: for an
    /// announcement the tag byte and the 168 bytes of the header, and for the transaction
    /// topics the relay caps of [`limits`].
    pub const fn max_transmit_size(self) -> usize {
        match self {
            Topic::BlockAnnounce => ANNOUNCE_WIRE_BYTES,
            Topic::CoinTxs => limits::MAX_COIN_TX_RELAY_BYTES,
            Topic::ProofRequests => limits::MAX_PROOF_REQUEST_RELAY_BYTES,
        }
    }
}

/// A gossiped message that passed the precheck.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gossip {
    /// The header of a block that its miner or a relaying peer announces. The block
    /// itself is fetched with `GetBlocks`. Boxed so a queued message is two words.
    Announce(Box<CheckedAnnounce>),
    /// A transaction for the mempool. Boxed so a queued message is two words.
    Tx(Box<CheckedTx>),
}

/// First byte of a gossiped announcement on the wire, then the 168 bytes of the header.
const ANNOUNCE_TAG: u8 = 0;
/// First byte of a gossiped transaction on the wire, then the borsh of the transaction.
const TX_TAG: u8 = 1;

/// Bytes of an announcement on the wire: the tag and the header.
pub const ANNOUNCE_WIRE_BYTES: usize = 1 + BlockHeader::SIZE;

impl Gossip {
    /// The topic the message travels on.
    pub fn topic(&self) -> Topic {
        match self {
            Gossip::Announce(_) => Topic::BlockAnnounce,
            Gossip::Tx(checked) if matches!(checked.tx.body.kind, TxKind::ProofRequest { .. }) => {
                Topic::ProofRequests
            }
            Gossip::Tx(_) => Topic::CoinTxs,
        }
    }

    /// The bytes of the message on the wire. An announcement is the tag and the raw
    /// header, a transaction is the tag and its borsh.
    pub fn to_wire(&self) -> Result<Vec<u8>, borsh::io::Error> {
        match self {
            Gossip::Announce(announce) => {
                let mut bytes = Vec::with_capacity(ANNOUNCE_WIRE_BYTES);
                bytes.push(ANNOUNCE_TAG);
                bytes.extend_from_slice(zerocopy::IntoBytes::as_bytes(&announce.header));
                Ok(bytes)
            }
            Gossip::Tx(checked) => {
                let mut bytes = vec![TX_TAG];
                checked.tx.serialize(&mut bytes)?;
                Ok(bytes)
            }
        }
    }
}

/// Why a received gossip message is dropped before it reaches the node.
#[derive(Debug, Error)]
pub enum GossipError {
    /// The message is longer than the limit of its topic.
    #[error("{topic:?} message of {found} bytes, the limit is {limit}")]
    Oversized {
        topic: Topic,
        found: usize,
        limit: usize,
    },
    /// The item in the message fails the precheck.
    #[error(transparent)]
    Precheck(#[from] PrecheckError),
    /// The message belongs to another topic than the one it arrived on.
    #[error("a {found:?} message arrived on {topic:?}")]
    WrongTopic { topic: Topic, found: Topic },
}

/// What to report about a peer that sent an item with this precheck failure.
pub fn blame(error: &PrecheckError) -> Misbehavior {
    match error {
        PrecheckError::Block(_) => Misbehavior::InvalidBlock,
        PrecheckError::Tx(_) => Misbehavior::InvalidTx,
        PrecheckError::Oversized { .. } | PrecheckError::Malformed(_) => Misbehavior::Malformed,
    }
}

impl GossipError {
    /// What to report about the sender.
    pub fn misbehavior(&self) -> Misbehavior {
        match self {
            GossipError::Precheck(error) => blame(error),
            GossipError::Oversized { .. } | GossipError::WrongTopic { .. } => {
                Misbehavior::Malformed
            }
        }
    }
}

impl Gossip {
    /// Runs the precheck on a message that arrived on `topic`. The size limit is
    /// checked before any decoding, and an announcement on a transaction topic is
    /// refused before its header is read.
    pub fn decode(
        topic: Topic,
        bytes: &[u8],
        params: &ConsensusParams,
        scratch: &mut Scratch,
    ) -> Result<Self, GossipError> {
        let limit = topic.max_transmit_size();
        if bytes.len() > limit {
            return Err(GossipError::Oversized {
                topic,
                found: bytes.len(),
                limit,
            });
        }
        let Some((tag, payload)) = bytes.split_first() else {
            return Err(PrecheckError::Malformed("empty message".to_owned()).into());
        };
        let message = match *tag {
            ANNOUNCE_TAG if topic != Topic::BlockAnnounce => {
                return Err(GossipError::WrongTopic {
                    topic,
                    found: Topic::BlockAnnounce,
                });
            }
            ANNOUNCE_TAG => {
                let checked = precheck::check_announce_bytes(payload, params)?;
                Gossip::Announce(Box::new(checked))
            }
            TX_TAG => {
                let checked = precheck::check_tx_bytes(payload, params.chain_id, scratch)?;
                Gossip::Tx(Box::new(checked))
            }
            other => {
                return Err(PrecheckError::Malformed(format!("unknown tag {other}")).into());
            }
        };
        match message.topic() {
            found if found == topic => Ok(message),
            found => Err(GossipError::WrongTopic { topic, found }),
        }
    }
}

/// What the transport does with a received gossip message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acceptance {
    /// Valid: relay it.
    Accept,
    /// Not invalid but not useful, such as a duplicate: drop it without penalty.
    Ignore,
    /// Invalid: drop it and penalize the sender.
    Reject,
}

/// Behaviour of a peer that lowers its score.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Misbehavior {
    /// Sent bytes that do not decode.
    Malformed,
    /// Sent a block that breaks a rule.
    InvalidBlock,
    /// Sent a transaction that breaks a rule.
    InvalidTx,
    /// Did not answer a request in time.
    Unresponsive,
}

impl Misbehavior {
    /// Points taken off the score of a peer that behaved so, the penalty constants of
    /// [`limits`].
    pub const fn penalty(self) -> i64 {
        match self {
            Misbehavior::Malformed => PENALTY_MALFORMED,
            Misbehavior::InvalidBlock => PENALTY_INVALID_BLOCK,
            Misbehavior::InvalidTx => PENALTY_INVALID_TX,
            Misbehavior::Unresponsive => PENALTY_UNRESPONSIVE,
        }
    }
}

/// What the transport remembers about the behaviour of peers: a score per connected
/// peer that starts at 0 and only goes down. The transport thread owns it. [`forget`]
/// removes the entry of a peer on disconnect, so the table holds at most
/// `max_inbound + max_outbound` entries, the bound of [`Peers`]. It is a `BTreeMap` for
/// the same reason.
#[derive(Debug, Default)]
pub struct Scores {
    pub by_peer: BTreeMap<PeerIx, i64>,
}

/// Whether a peer may stay after a penalty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum Standing {
    Tolerated,
    /// The score reached [`BAN_SCORE`]: the swarm of pouw-node#85 disconnects the peer
    /// and refuses it for [`BAN_DURATION`].
    Banned,
}

/// Lowers the score of `peer` by the penalty of `why`.
pub fn penalize(scores: &mut Scores, peer: PeerIx, why: Misbehavior) -> Standing {
    let score = scores.by_peer.entry(peer).or_insert(0);
    *score = score.saturating_sub(why.penalty());
    if *score <= BAN_SCORE {
        Standing::Banned
    } else {
        Standing::Tolerated
    }
}

/// Forgets the score of a peer that disconnected, so the table holds only connected
/// peers.
pub fn forget(scores: &mut Scores, peer: PeerIx) {
    scores.by_peer.remove(&peer);
}

/// How a request to a peer failed at the transport. The variants are those of the
/// libp2p request-response `OutboundFailure`, so the swarm of pouw-node#85 maps its
/// error one to one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TransportFailure {
    #[error("the dial failed")]
    DialFailure,
    #[error("the connection closed before the answer")]
    ConnectionClosed,
    #[error("the peer does not speak the protocol")]
    UnsupportedProtocols,
    #[error("i/o error: {0:?}")]
    Io(io::ErrorKind),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NetworkError {
    #[error("peer {0:?} is not connected")]
    NotConnected(PeerIx),
    #[error("the request timed out")]
    Timeout,
    #[error("the transport has stopped")]
    Stopped,
    #[error("transport failure: {0}")]
    Transport(#[from] TransportFailure),
    /// The answer arrived but fails the precheck, or does not decode.
    #[error("the answer was refused: {0:?}")]
    BadAnswer(Misbehavior),
}

/// Names one request of the node to a peer; the answer carries it back.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub u64);

/// Names one gossip message from the moment the transport hands it to the node until
/// the node's [`Command::Validate`]. The transport numbers the messages it forwards and
/// wraps around at `u64::MAX`; the swarm of pouw-node#85 maps the number to the
/// gossipsub `MessageId` it passes to `report_message_validation_result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub u64);

/// Names one sync request of a peer from the moment the transport hands it to the node
/// until the node's [`Command::Answer`]. The transport numbers the requests it forwards
/// and wraps around at `u64::MAX`; the swarm of pouw-node#85 keeps the libp2p response
/// channel of each request in a table under this number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServeId(pub u64);

/// A call from the node to the transport, delivered to [`Outbound`].
#[derive(Debug)]
pub enum Command {
    /// Send `message` to the peers of its topic.
    Broadcast(Gossip),
    /// Send our [`Status`] to `peer`, once per connection, right after it connects.
    Status { peer: PeerIx, status: Box<Status> },
    /// Close the connection to `peer` for `reason`. A disconnect is not a penalty: a
    /// peer of another chain is not misbehaving.
    Disconnect {
        peer: PeerIx,
        reason: DisconnectReason,
    },
    /// Ask one peer. The transport answers later with [`Inbound::Response`] of `id`.
    Request {
        id: RequestId,
        /// The peer to ask.
        peer: PeerIx,
        /// What to ask.
        request: SyncRequest,
    },
    /// Lower the score of `peer`.
    Report(PeerIx, Misbehavior),
    /// The node's verdict on the gossip message `id` that `from` sent on `topic`. The
    /// transport relays an `Accept`, drops an `Ignore`, and drops a `Reject` and lowers
    /// the score of `from` by the [`rejection`] of `topic`.
    Validate {
        id: MessageId,
        from: PeerIx,
        topic: Topic,
        acceptance: Acceptance,
    },
    /// The answer to the sync request `id`. The transport sends it on the response
    /// channel it holds under `id`, to the peer that asked.
    Answer { id: ServeId, response: SyncResponse },
}

/// The node's end of the transport: a bounded channel of capacity
/// [`COMMAND_CAPACITY`](crate::node::COMMAND_CAPACITY). The node sends with
/// [`send`], which never waits.
pub type Network = mpsc::Sender<Command>;

/// The transport's end of a [`Network`]: the commands the node issues.
pub type Outbound = mpsc::Receiver<Command>;

/// The transport has stopped, so a [`Command`] has nowhere to go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("the transport has stopped")]
pub struct TransportGone;

/// What [`send`] did with a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    Queued,
    /// The command channel was full, so the command is gone and counted in
    /// [`Metrics::dropped_commands`]. Gossip and sync are best effort, but a caller that
    /// keeps state for the command (a pending request) must not keep it.
    Dropped,
}

/// Hands `command` to the transport without waiting for it. A full channel drops the
/// command: the loop never waits for a transport that may itself be waiting for the
/// loop.
pub fn send(
    network: &Network,
    command: Command,
    metrics: &mut Metrics,
) -> Result<Delivery, TransportGone> {
    match network.try_send(command) {
        Ok(()) => Ok(Delivery::Queued),
        Err(mpsc::error::TrySendError::Full(command)) => {
            metrics.dropped_commands = metrics.dropped_commands.saturating_add(1);
            warn!(?command, "command channel full, command dropped");
            Ok(Delivery::Dropped)
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportGone),
    }
}

/// A call from the transport to the node, delivered to the node's event loop.
#[derive(Debug)]
pub enum Inbound {
    /// Validate a gossip message before the transport relays it; the node answers with
    /// [`Command::Validate`] of `id`.
    Gossip {
        id: MessageId,
        /// The sender.
        from: PeerIx,
        message: Gossip,
    },
    /// The [`Status`] of a peer, its first message after it connects. The node answers a
    /// peer it cannot stay connected to with [`Command::Disconnect`].
    Status {
        from: PeerIx,
        status: Box<Status>,
    },
    /// Answer a sync request of a peer with [`Command::Answer`] of `serve`.
    Request {
        /// The asking peer.
        from: PeerIx,
        serve: ServeId,
        /// What it asks.
        request: SyncRequest,
    },
    /// The answer to the [`Command::Request`] of `id`.
    Response {
        id: RequestId,
        result: Result<Fetched, NetworkError>,
    },
    /// A new peer. `peer_id` is the hex text of its libp2p id, which the node publishes
    /// in its event log and never parses.
    PeerConnected {
        peer: PeerIx,
        peer_id: Box<str>,
    },
    PeerDisconnected {
        peer: PeerIx,
        peer_id: Box<str>,
    },
}

/// One gossip topic the transport subscribes to, with the `max_transmit_size` it sets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub topic: Topic,
    /// The protocol id of the topic on this network.
    pub id: String,
    pub max_transmit_size: usize,
}

/// Every topic a node subscribes to.
pub const TOPICS: [Topic; 3] = [Topic::BlockAnnounce, Topic::CoinTxs, Topic::ProofRequests];

/// The topics of `network` with their ids and limits.
pub fn subscriptions(network: &NetworkName) -> [Subscription; TOPICS.len()] {
    TOPICS.map(|topic| Subscription {
        topic,
        id: protocol::protocol_id(network, topic.name()),
        max_transmit_size: topic.max_transmit_size(),
    })
}

/// The topic whose protocol id is `text`, if the node subscribes to it.
pub fn topic_named(subscriptions: &[Subscription], text: &str) -> Option<Topic> {
    subscriptions
        .iter()
        .find(|subscription| subscription.id == text)
        .map(|subscription| subscription.topic)
}

/// What the swarm hands over to the transport: raw bytes and peer identities the node
/// loop has not seen yet.
#[derive(Debug)]
pub enum Wire {
    /// A gossip message that arrived on the topic named `topic`.
    Gossip {
        topic: String,
        from: Vec<u8>,
        bytes: Vec<u8>,
    },
    /// The status message of a peer.
    Status {
        from: Vec<u8>,
        bytes: Vec<u8>,
    },
    /// A sync request of a peer.
    SyncRequest {
        from: Vec<u8>,
        bytes: Vec<u8>,
    },
    /// The answer to the request `id` of the node.
    SyncResponse {
        id: RequestId,
        bytes: Vec<u8>,
    },
    PeerConnected(Vec<u8>),
    PeerDisconnected(Vec<u8>),
}

/// The transport's end of the channel the swarm feeds, of capacity [`WIRE_CAPACITY`].
/// The swarm sends with `send().await`, so a full channel stops its reads.
pub type WireIn = mpsc::Receiver<Wire>;

/// What became of the bytes of one gossip message.
#[derive(Debug)]
#[must_use]
pub enum Received {
    /// The node loop has the message; its verdict arrives as [`Command::Validate`].
    Forwarded,
    /// The bytes are not a valid message; the sender deserves
    /// [`GossipError::misbehavior`].
    Refused(GossipError),
    /// The node loop is gone.
    NodeGone,
}

/// Runs the precheck on the bytes of a message from `from` on `topic` and hands the
/// checked message to the node loop as the message `id`. Waits while the p2p channel is
/// full.
pub async fn on_gossip_bytes(
    topic: Topic,
    from: PeerIx,
    id: MessageId,
    bytes: &[u8],
    params: &ConsensusParams,
    scratch: &mut Scratch,
    inbound: &mpsc::Sender<Inbound>,
) -> Received {
    let message = match Gossip::decode(topic, bytes, params, scratch) {
        Ok(message) => message,
        Err(error) => return Received::Refused(error),
    };
    match inbound.send(Inbound::Gossip { id, from, message }).await {
        Ok(()) => Received::Forwarded,
        Err(mpsc::error::SendError(_)) => Received::NodeGone,
    }
}

/// What to report about a peer whose message on `topic` the node rejected.
pub fn rejection(topic: Topic) -> Misbehavior {
    match topic {
        Topic::BlockAnnounce => Misbehavior::InvalidBlock,
        Topic::CoinTxs | Topic::ProofRequests => Misbehavior::InvalidTx,
    }
}

/// What became of the bytes of one sync request.
#[derive(Debug)]
#[must_use]
pub enum SyncReceived {
    /// The node loop has the request; its answer arrives as [`Command::Answer`].
    Forwarded,
    /// The bytes are not a valid request; report this about the sender.
    Refused(Misbehavior),
    /// The node loop is gone.
    NodeGone,
}

/// Decodes the bytes of a sync request from `from` and hands it to the node loop as the
/// request `serve`. Waits while the p2p channel is full.
pub async fn on_sync_request_bytes(
    from: PeerIx,
    serve: ServeId,
    bytes: &[u8],
    inbound: &mpsc::Sender<Inbound>,
) -> SyncReceived {
    let request = match protocol::decode_request(bytes) {
        Ok(request) => request,
        Err(error) => {
            debug!(%error, "a sync request that does not decode");
            return SyncReceived::Refused(Misbehavior::Malformed);
        }
    };
    match inbound
        .send(Inbound::Request {
            from,
            serve,
            request,
        })
        .await
    {
        Ok(()) => SyncReceived::Forwarded,
        Err(mpsc::error::SendError(_)) => SyncReceived::NodeGone,
    }
}

/// Everything the transport thread owns.
#[derive(Debug, Default)]
pub struct Transport {
    pub peers: Peers,
    pub scores: Scores,
    /// The id of the next gossip message handed to the node.
    pub next_message: u64,
    /// The id of the next sync request handed to the node.
    pub next_serve: u64,
    /// Buffers of the precheck, which runs on this thread.
    pub scratch: Scratch,
}

/// The next thing for the transport thread to handle.
#[derive(Debug)]
enum Step {
    Command(Command),
    Wire(Wire),
}

/// What the transport needs to know about the network it joins.
#[derive(Debug, Clone)]
pub struct TransportConfig {
    /// Names the protocol ids, see [`protocol::protocol_id`].
    pub network: NetworkName,
    /// Multiaddresses to listen on.
    pub listen: Vec<String>,
    /// Multiaddresses of the nodes to dial first and to seed discovery with.
    pub bootnodes: Vec<String>,
    pub limits: PeerLimits,

    /// Directory of the node key, see [`identity`].
    pub data_dir: PathBuf,
}

/// Builds the libp2p swarm of the node and returns the channel it feeds.
///
/// To build, pouw-node#85:
/// - identify, so a peer learns the listen addresses and the protocol ids of another
/// - Kademlia with the bootnodes as its first entries, k-buckets of
///   [`PeerLimits::kademlia_bucket_size`] (20) entries, so the routing table is bounded
/// - gossipsub with the topics of [`subscriptions`], `max_transmit_size` per topic,
///   mesh degree [`PeerLimits::mesh_d`] (6) and validation mode `Strict` with
///   `validate_messages`, so a message is relayed only after [`Command::Validate`]
/// - request-response for [`protocol::SYNC`] and for [`protocol::STATUS`]
/// - a connection limit of [`PeerLimits::max_outbound`] dialed peers and
///   [`PeerLimits::max_inbound`] accepted peers, refused beyond them
/// - a ban list that holds a peer for [`BAN_DURATION`] after [`Standing::Banned`], and
///   refuses its connections while it holds
///
/// Edge cases: a peer that is dialed and dials at the same time is one peer
/// ([`connect`] returns `None` for the second connection). A peer whose
/// [`protocol::Status`] fails [`Status::compatible`] is disconnected by
/// [`Command::Disconnect`] and is not banned.
///
/// Test: two swarms on one machine with the same network connect, exchange `Status`
/// and see each other's gossip. A swarm of another network is never connected.
pub fn start_swarm(config: &TransportConfig) -> Result<WireIn, swarm::SwarmError> {
    swarm::start(config)
}

/// The transport thread: serves the commands of `outbound` and the messages of the
/// swarm until every [`Network`] is gone and the swarm side ends. The libp2p swarm of
/// [`start_swarm`] is pouw-node#85; until it exists no peer is connected, so every
/// request is answered with [`NetworkError::NotConnected`] and the swarm side is silent.
pub fn run_transport(
    config: &TransportConfig,
    params: &ConsensusParams,
    outbound: Outbound,
    inbound: &mpsc::Sender<Inbound>,
) -> Result<(), ComponentFault> {
    let wire = start_swarm(config).map_err(|error| ComponentFault::Swarm(Box::new(error)))?;
    serve(&config.network, params, outbound, wire, inbound)
}

/// Handles commands and wire messages one at a time on one thread, with commands
/// first, until both sources have ended. A message that cannot belong to the swarm (a
/// peer id over [`MAX_PEER_ID_BYTES`]) stops the transport with a fault, so a broken
/// swarm glue is not mistaken for a bad peer.
pub fn serve(
    network: &NetworkName,
    params: &ConsensusParams,
    mut outbound: Outbound,
    mut wire: WireIn,
    inbound: &mpsc::Sender<Inbound>,
) -> Result<(), ComponentFault> {
    let subscriptions = subscriptions(network);
    info!(?subscriptions, "gossip topics");
    let runtime = runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        let mut transport = Transport::default();
        while let Some(step) = next_step(&mut outbound, &mut wire).await {
            match step {
                Step::Command(command) => on_command(&mut transport, command, inbound).await?,
                Step::Wire(message) => {
                    on_wire(&mut transport, params, &subscriptions, message, inbound).await?;
                }
            }
        }
        Ok(())
    })
}

/// The next command, else the next wire message; `None` when both sources have ended.
async fn next_step(outbound: &mut Outbound, wire: &mut WireIn) -> Option<Step> {
    poll_fn(|cx| {
        let commands = outbound.poll_recv(cx);
        if let Poll::Ready(Some(command)) = commands {
            return Poll::Ready(Some(Step::Command(command)));
        }
        let messages = wire.poll_recv(cx);
        if let Poll::Ready(Some(message)) = messages {
            return Poll::Ready(Some(Step::Wire(message)));
        }
        match (commands, messages) {
            (Poll::Ready(None), Poll::Ready(None)) => Poll::Ready(None),
            _ => Poll::Pending,
        }
    })
    .await
}

/// Hands `message` to the node loop, waiting while the p2p channel is full.
async fn to_node(inbound: &mpsc::Sender<Inbound>, message: Inbound) -> Result<(), ComponentFault> {
    inbound
        .send(message)
        .await
        .map_err(|mpsc::error::SendError(_)| ComponentFault::NodeGone)
}

async fn on_command(
    transport: &mut Transport,
    command: Command,
    inbound: &mpsc::Sender<Inbound>,
) -> Result<(), ComponentFault> {
    match command {
        Command::Request { id, peer, .. } => {
            let result = Err(NetworkError::NotConnected(peer));
            to_node(inbound, Inbound::Response { id, result }).await?;
        }
        Command::Report(peer, why) => apply_penalty(transport, peer, why),
        Command::Validate {
            from,
            topic,
            acceptance: Acceptance::Reject,
            ..
        } => apply_penalty(transport, from, rejection(topic)),
        Command::Validate {
            id,
            topic,
            acceptance,
            ..
        } => debug!(?id, ?topic, ?acceptance, "verdict on a gossip message"),
        Command::Answer { id, response } => {
            debug!(?id, ?response, "answer to a sync request");
        }
        Command::Status { peer, status } => debug!(?peer, ?status, "no peer to send status to"),
        Command::Disconnect { peer, reason } => {
            debug!(?peer, %reason, "no connection to close");
        }
        command @ Command::Broadcast(_) => debug!(?command, "no peer to send to"),
    }
    Ok(())
}

async fn on_wire(
    transport: &mut Transport,
    params: &ConsensusParams,
    subscriptions: &[Subscription],
    message: Wire,
    inbound: &mpsc::Sender<Inbound>,
) -> Result<(), ComponentFault> {
    match message {
        Wire::Gossip { topic, from, bytes } => {
            let from = PeerId::from_bytes(&from)?;
            let Some(topic) = topic_named(subscriptions, &topic) else {
                warn!(topic, "message on a topic the node did not subscribe to");
                return Ok(());
            };
            let Some(peer) = transport.peers.by_id.get(&from).copied() else {
                warn!(?from, "gossip from a peer that is not connected");
                return Ok(());
            };
            let id = MessageId(transport.next_message);
            transport.next_message = transport.next_message.wrapping_add(1);
            match on_gossip_bytes(
                topic,
                peer,
                id,
                &bytes,
                params,
                &mut transport.scratch,
                inbound,
            )
            .await
            {
                Received::Forwarded => {}
                Received::Refused(error) => {
                    warn!(%error, ?from, "message refused before the node");
                    apply_penalty(transport, peer, error.misbehavior());
                }
                Received::NodeGone => return Err(ComponentFault::NodeGone),
            }
        }
        Wire::Status { from, bytes } => {
            let from = PeerId::from_bytes(&from)?;
            let Some(peer) = transport.peers.by_id.get(&from).copied() else {
                warn!(?from, "status from a peer that is not connected");
                return Ok(());
            };
            match protocol::decode_status(&bytes) {
                Ok(status) => {
                    let status = Box::new(status);
                    to_node(inbound, Inbound::Status { from: peer, status }).await?;
                }
                Err(error) => {
                    warn!(%error, ?from, "status refused before the node");
                    apply_penalty(transport, peer, Misbehavior::Malformed);
                }
            }
        }
        Wire::SyncRequest { from, bytes } => {
            let from = PeerId::from_bytes(&from)?;
            let Some(peer) = transport.peers.by_id.get(&from).copied() else {
                warn!(?from, "sync request from a peer that is not connected");
                return Ok(());
            };
            let serve = ServeId(transport.next_serve);
            transport.next_serve = transport.next_serve.wrapping_add(1);
            match on_sync_request_bytes(peer, serve, &bytes, inbound).await {
                SyncReceived::Forwarded => {}
                SyncReceived::Refused(why) => {
                    warn!(?why, ?from, "sync request refused before the node");
                    apply_penalty(transport, peer, why);
                }
                SyncReceived::NodeGone => return Err(ComponentFault::NodeGone),
            }
        }
        Wire::SyncResponse { id, bytes } => {
            let result = precheck_response(&bytes, params, &mut transport.scratch);
            to_node(inbound, Inbound::Response { id, result }).await?;
        }
        Wire::PeerConnected(bytes) => {
            let id = PeerId::from_bytes(&bytes)?;
            if let Some(peer) = connect(&mut transport.peers, id)? {
                let peer_id = Hex(id.as_bytes()).to_string().into_boxed_str();
                to_node(inbound, Inbound::PeerConnected { peer, peer_id }).await?;
            }
        }
        Wire::PeerDisconnected(bytes) => {
            let id = PeerId::from_bytes(&bytes)?;
            if let Some(peer) = disconnect(&mut transport.peers, &id) {
                forget(&mut transport.scores, peer);
                let peer_id = Hex(id.as_bytes()).to_string().into_boxed_str();
                to_node(inbound, Inbound::PeerDisconnected { peer, peer_id }).await?;
            }
        }
    }
    Ok(())
}

/// Decodes and prechecks the bytes of an answer to a request of the node.
fn precheck_response(
    bytes: &[u8],
    params: &ConsensusParams,
    scratch: &mut Scratch,
) -> Result<Fetched, NetworkError> {
    let response = protocol::decode_response(bytes).map_err(|error| {
        debug!(%error, "an answer that does not decode");
        NetworkError::BadAnswer(Misbehavior::Malformed)
    })?;
    precheck::check_response(response, params, scratch)
        .map_err(|error| NetworkError::BadAnswer(blame(&error)))
}

/// Lowers the score of `peer`, unless it has disconnected since the command was issued.
fn apply_penalty(transport: &mut Transport, peer: PeerIx, why: Misbehavior) {
    let Some(id) = transport.peers.by_ix.get(&peer).copied() else {
        debug!(?peer, ?why, "penalty for a peer that left");
        return;
    };
    match penalize(&mut transport.scores, peer, why) {
        Standing::Tolerated => debug!(?id, ?why, "peer penalized"),
        Standing::Banned => warn!(
            ?id,
            ?why,
            "pouw-node#85: peer banned, no swarm to disconnect it"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::{future::Future, pin::pin};

    use pouw_crypto::{Address, FIELD_INPUT_BYTES, Hash32, SigningKey};
    use pouw_types::{
        Amount, ChainId, CircuitId, Nonce, SignedTx, Target, TxBody, TxId, U32, U64,
        protocol::{MAX_PUBLIC_INPUTS, MAX_WITNESS_BYTES},
        sign_body,
    };

    use crate::mempool::MAX_RELAY_CIRCUIT_BYTES;

    use super::*;

    fn params() -> ConsensusParams {
        let target = Target([0xff; 32]);
        ConsensusParams {
            chain_id: ChainId(1),
            initial_subsidy: Amount(50),
            halving_interval: 100,
            target_block_secs: 10,
            half_life_secs: 100,
            initial_target: target,
            pow_limit: target,
            max_future_secs: 300,
            fee_per_public_input: Amount(0),
            fee_per_witness_kib: Amount(0),
        }
    }

    fn tx(kind: TxKind) -> SignedTx {
        let key = SigningKey::from_seed([1; 32]);
        sign_body(
            &TxBody {
                chain_id: ChainId(1),
                sender: key.address(),
                nonce: Nonce(0),
                fee: Amount(1),
                kind,
            },
            &key,
        )
    }

    fn checked_tx(kind: TxKind) -> CheckedTx {
        let tx = tx(kind);
        let txid = pouw_types::txid(&tx);
        CheckedTx { tx, txid }
    }

    fn decode(topic: Topic, bytes: &[u8]) -> Result<Gossip, GossipError> {
        Gossip::decode(topic, bytes, &params(), &mut Scratch::default())
    }

    fn devnet() -> NetworkName {
        NetworkName::try_from("devnet".to_owned()).unwrap()
    }

    /*
    fn config() -> TransportConfig {
        TransportConfig {
            network: devnet(),
            listen: vec![],
            bootnodes: vec![],
            limits: PeerLimits::default(),
        }
    }
    */

    fn announce_header() -> BlockHeader {
        BlockHeader {
            version: U32::new(1),
            chain_id: U32::new(1),
            system_id: U64::new(0),
            height: U64::new(1),
            parent: pouw_types::BlockId::ZERO,
            timestamp: U64::new(1),
            miner: Address([9; 32]),
            tx_root: Hash32::ZERO,
            target: Target([0xff; 32]),
            nonce: U64::new(0),
        }
    }

    fn announce_bytes() -> Vec<u8> {
        let mut bytes = vec![ANNOUNCE_TAG];
        bytes.extend_from_slice(zerocopy::IntoBytes::as_bytes(&announce_header()));
        bytes
    }

    fn peer() -> PeerId {
        PeerId::from_bytes(b"p").unwrap()
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(future)
    }

    fn request_to(id: u64) -> Command {
        Command::Request {
            id: RequestId(id),
            peer: PeerIx(0),
            request: SyncRequest::GetBlocks(GetBlocks { ids: vec![] }),
        }
    }

    #[test]
    fn peer_id_keeps_its_bytes_and_bounds_them() {
        let bytes = [7u8; MAX_PEER_ID_BYTES];
        assert_eq!(PeerId::from_bytes(&bytes).unwrap().as_bytes(), bytes);
        assert_eq!(PeerId::from_bytes(&[]).unwrap().as_bytes(), b"");
        let mut longest_libp2p = vec![0x12, 64];
        longest_libp2p.extend([9; 64]);
        assert_eq!(
            PeerId::from_bytes(&longest_libp2p).unwrap().as_bytes(),
            longest_libp2p
        );
        assert_eq!(
            PeerId::from_bytes(&[0; MAX_PEER_ID_BYTES + 1]),
            Err(PeerIdTooLong(MAX_PEER_ID_BYTES + 1))
        );
        assert_ne!(PeerId::from_bytes(&[1]), PeerId::from_bytes(&[1, 0]));
        assert_eq!(format!("{:?}", peer()), "PeerId(70)");
    }

    #[test]
    fn a_peer_gets_one_index_that_is_never_reused() {
        let mut peers = Peers::default();
        let other = PeerId::from_bytes(b"q").unwrap();
        assert_eq!(connect(&mut peers, peer()), Ok(Some(PeerIx(0))));
        assert_eq!(connect(&mut peers, peer()), Ok(None));
        assert_eq!(connect(&mut peers, other), Ok(Some(PeerIx(1))));
        assert_eq!(disconnect(&mut peers, &peer()), Some(PeerIx(0)));
        assert_eq!(disconnect(&mut peers, &peer()), None);
        assert!(!peers.by_ix.contains_key(&PeerIx(0)));
        assert_eq!(connect(&mut peers, peer()), Ok(Some(PeerIx(2))));
        assert_eq!(peers.by_ix.len(), 2);
        assert_eq!(peers.by_id.len(), 2);
        peers.next = u32::MAX;
        assert_eq!(
            connect(&mut peers, PeerId::from_bytes(b"r").unwrap()),
            Err(PeerIxExhausted)
        );
    }

    #[test]
    fn each_message_has_its_topic() {
        let transfer = Gossip::Tx(Box::new(checked_tx(TxKind::Transfer {
            to: Address([2; 32]),
            amount: Amount(1),
        })));
        let request = Gossip::Tx(Box::new(checked_tx(TxKind::ProofRequest {
            circuit: CircuitId(TxId(Hash32::ZERO)),
            public_inputs: vec![],
            witness: Box::from([]),
        })));
        assert_eq!(transfer.topic(), Topic::CoinTxs);
        assert_eq!(request.topic(), Topic::ProofRequests);
        assert_eq!(Topic::BlockAnnounce.name(), "block-announce");
        assert_eq!(
            protocol::protocol_id(&devnet(), Topic::BlockAnnounce.name()),
            "/pouw/devnet/block-announce/1"
        );
    }

    #[test]
    fn a_topic_limit_carries_the_largest_valid_message() {
        let circuit = Gossip::Tx(Box::new(checked_tx(TxKind::RegisterCircuit {
            system: pouw_types::ProofSystem::Groth16,
            constraint_count: pouw_types::ConstraintCount(1),
            verifying_key: Box::from([]),
            circuit: vec![0; MAX_RELAY_CIRCUIT_BYTES].into_boxed_slice(),
        })));
        let request = Gossip::Tx(Box::new(checked_tx(TxKind::ProofRequest {
            circuit: CircuitId(TxId(Hash32::ZERO)),
            public_inputs: vec![pouw_crypto::FieldInput([0; FIELD_INPUT_BYTES]); MAX_PUBLIC_INPUTS],
            witness: vec![0; MAX_WITNESS_BYTES].into_boxed_slice(),
        })));
        for message in [circuit, request] {
            let bytes = message.to_wire().unwrap();
            let topic = message.topic();
            assert!(bytes.len() <= topic.max_transmit_size());
            assert!(matches!(decode(topic, &bytes), Ok(decoded) if decoded == message));
        }
        assert_eq!(Topic::BlockAnnounce.max_transmit_size(), 169);
    }

    #[test]
    fn decode_refuses_by_size_before_parsing() {
        let limit = Topic::CoinTxs.max_transmit_size();
        let error = decode(Topic::CoinTxs, &vec![0; limit + 1]).unwrap_err();
        assert!(matches!(
            error,
            GossipError::Oversized { topic: Topic::CoinTxs, found, limit: found_limit }
                if found == limit + 1 && found_limit == limit
        ));
        assert_eq!(error.misbehavior(), Misbehavior::Malformed);
        assert!(matches!(
            decode(Topic::CoinTxs, &[0xff]),
            Err(GossipError::Precheck(PrecheckError::Malformed(_)))
        ));
    }

    #[test]
    fn decode_refuses_a_message_on_the_wrong_topic() {
        let transfer = Gossip::Tx(Box::new(checked_tx(TxKind::Transfer {
            to: Address([2; 32]),
            amount: Amount(1),
        })));
        let bytes = transfer.to_wire().unwrap();
        assert!(matches!(
            decode(Topic::ProofRequests, &bytes),
            Err(GossipError::WrongTopic {
                topic: Topic::ProofRequests,
                found: Topic::CoinTxs,
            })
        ));
    }

    #[test]
    fn a_full_command_channel_drops_the_command_and_counts_it() {
        let (network, mut outbound) = mpsc::channel(1);
        let mut metrics = Metrics::default();
        assert_eq!(
            send(&network, request_to(7), &mut metrics),
            Ok(Delivery::Queued)
        );
        assert_eq!(
            send(&network, request_to(8), &mut metrics),
            Ok(Delivery::Dropped)
        );
        assert_eq!(metrics.dropped_commands, 1);
        assert!(matches!(
            outbound.try_recv(),
            Ok(Command::Request {
                id: RequestId(7),
                ..
            })
        ));
        assert!(outbound.try_recv().is_err());
        drop(outbound);
        let report = Command::Report(PeerIx(0), Misbehavior::Malformed);
        assert_eq!(send(&network, report, &mut metrics), Err(TransportGone));
        assert_eq!(metrics.dropped_commands, 1);
    }

    #[test]
    fn without_a_transport_a_request_is_answered_as_not_connected() {
        let (network, outbound) = mpsc::channel(4);
        let (inbound, mut inbox) = mpsc::channel(4);
        let mut metrics = Metrics::default();
        let report = Command::Report(PeerIx(0), Misbehavior::Malformed);
        send(&network, request_to(3), &mut metrics).unwrap();
        send(&network, report, &mut metrics).unwrap();
        drop(network);
        let (_, wire) = mpsc::channel(WIRE_CAPACITY);
        serve(&devnet(), &params(), outbound, wire, &inbound).unwrap();
        assert!(matches!(
            inbox.try_recv(),
            Ok(Inbound::Response {
                id: RequestId(3),
                result: Err(NetworkError::NotConnected(PeerIx(0))),
            })
        ));
        assert!(inbox.try_recv().is_err());
    }

    fn transfer_bytes() -> Vec<u8> {
        let message = Gossip::Tx(Box::new(checked_tx(TxKind::Transfer {
            to: Address([2; 32]),
            amount: Amount(1),
        })));
        message.to_wire().unwrap()
    }

    #[test]
    fn subscriptions_carry_the_topic_texts_and_limits() {
        let table = subscriptions(&devnet());
        assert_eq!(table.clone().map(|s| s.topic), TOPICS);
        assert_eq!(
            table.clone().map(|s| s.max_transmit_size),
            TOPICS.map(Topic::max_transmit_size)
        );
        assert_eq!(
            topic_named(&table, "/pouw/devnet/coin-txs/1"),
            Some(Topic::CoinTxs)
        );
        assert_eq!(topic_named(&table, "/pouw/other/coin-txs/1"), None);
    }

    #[test]
    fn gossip_bytes_reach_the_node_with_their_message_id() {
        let (inbound, mut inbox) = mpsc::channel(4);
        let received = block_on(on_gossip_bytes(
            Topic::CoinTxs,
            PeerIx(4),
            MessageId(7),
            &transfer_bytes(),
            &params(),
            &mut Scratch::default(),
            &inbound,
        ));
        assert!(matches!(received, Received::Forwarded));
        let Ok(Inbound::Gossip { id, from, message }) = inbox.try_recv() else {
            panic!("the node got no gossip");
        };
        assert_eq!(
            (id, from, message.topic()),
            (MessageId(7), PeerIx(4), Topic::CoinTxs)
        );
    }

    #[test]
    fn a_full_p2p_channel_makes_the_transport_wait_instead_of_queueing_more() {
        block_on(async {
            let (inbound, mut inbox) = mpsc::channel(1);
            let filler = Inbound::PeerDisconnected {
                peer: PeerIx(0),
                peer_id: "00".into(),
            };
            inbound.send(filler).await.unwrap();
            let bytes = transfer_bytes();
            let params = params();
            let mut scratch = Scratch::default();
            let mut forwarding = pin!(on_gossip_bytes(
                Topic::CoinTxs,
                PeerIx(0),
                MessageId(0),
                &bytes,
                &params,
                &mut scratch,
                &inbound,
            ));
            let waiting = poll_fn(|cx| Poll::Ready(forwarding.as_mut().poll(cx).is_pending()));
            assert!(waiting.await, "a full channel must hold the sender back");
            assert!(matches!(
                inbox.recv().await,
                Some(Inbound::PeerDisconnected { .. })
            ));
            assert!(matches!(forwarding.await, Received::Forwarded));
            assert!(matches!(inbox.recv().await, Some(Inbound::Gossip { .. })));
        });
    }

    #[test]
    fn oversized_gossip_bytes_are_refused_and_never_reach_the_node() {
        let (inbound, mut inbox) = mpsc::channel(4);
        let limit = Topic::BlockAnnounce.max_transmit_size();
        let received = block_on(on_gossip_bytes(
            Topic::BlockAnnounce,
            PeerIx(0),
            MessageId(0),
            &vec![0; limit + 1],
            &params(),
            &mut Scratch::default(),
            &inbound,
        ));
        let Received::Refused(error @ GossipError::Oversized { .. }) = received else {
            panic!("an oversized message is refused");
        };
        assert_eq!(error.misbehavior(), Misbehavior::Malformed);
        assert!(inbox.try_recv().is_err());
        drop(inbox);
        assert!(matches!(
            block_on(on_gossip_bytes(
                Topic::CoinTxs,
                PeerIx(0),
                MessageId(1),
                &transfer_bytes(),
                &params(),
                &mut Scratch::default(),
                &inbound
            )),
            Received::NodeGone
        ));
    }

    #[test]
    fn malformed_or_misplaced_gossip_bytes_are_refused_and_never_reach_the_node() {
        let (inbound, mut inbox) = mpsc::channel(4);
        for (topic, bytes) in [
            (Topic::CoinTxs, vec![0xff]),
            (Topic::ProofRequests, transfer_bytes()),
        ] {
            let received = block_on(on_gossip_bytes(
                topic,
                PeerIx(0),
                MessageId(0),
                &bytes,
                &params(),
                &mut Scratch::default(),
                &inbound,
            ));
            assert!(matches!(
                received,
                Received::Refused(
                    GossipError::Precheck(PrecheckError::Malformed(_))
                        | GossipError::WrongTopic { .. }
                )
            ));
        }
        assert!(inbox.try_recv().is_err());
    }

    #[test]
    fn the_transport_turns_wire_messages_into_inbound_messages() {
        let (network, outbound) = mpsc::channel(4);
        let (inbound, mut inbox) = mpsc::channel(16);
        let (swarm, wire) = mpsc::channel(16);
        let topic = "/pouw/devnet/coin-txs/1".to_owned();
        let from = b"p".to_vec();
        let stranger = b"s".to_vec();
        let sync_request =
            borsh::to_vec(&SyncRequest::GetBlocks(GetBlocks { ids: vec![] })).unwrap();
        for message in [
            Wire::Gossip {
                topic: topic.clone(),
                from: from.clone(),
                bytes: transfer_bytes(),
            },
            Wire::PeerConnected(from.clone()),
            Wire::PeerConnected(from.clone()),
            Wire::Gossip {
                topic: topic.clone(),
                from: from.clone(),
                bytes: transfer_bytes(),
            },
            Wire::Gossip {
                topic: topic.clone(),
                from: from.clone(),
                bytes: vec![0xff],
            },
            Wire::Gossip {
                topic: "/other".to_owned(),
                from: from.clone(),
                bytes: transfer_bytes(),
            },
            Wire::Gossip {
                topic,
                from: stranger.clone(),
                bytes: transfer_bytes(),
            },
            Wire::SyncRequest {
                from: from.clone(),
                bytes: sync_request.clone(),
            },
            Wire::SyncRequest {
                from: stranger,
                bytes: sync_request,
            },
            Wire::PeerDisconnected(from.clone()),
            Wire::PeerDisconnected(from),
        ] {
            swarm.try_send(message).unwrap();
        }
        drop((swarm, network));
        serve(&devnet(), &params(), outbound, wire, &inbound).unwrap();
        assert!(matches!(
            inbox.try_recv(),
            Ok(Inbound::PeerConnected { peer: PeerIx(0), peer_id }) if &*peer_id == "70"
        ));
        assert!(matches!(
            inbox.try_recv(),
            Ok(Inbound::Gossip {
                id: MessageId(0),
                from: PeerIx(0),
                ..
            })
        ));
        assert!(matches!(
            inbox.try_recv(),
            Ok(Inbound::Request {
                from: PeerIx(0),
                serve: ServeId(0),
                ..
            })
        ));
        assert!(matches!(
            inbox.try_recv(),
            Ok(Inbound::PeerDisconnected { peer: PeerIx(0), peer_id }) if &*peer_id == "70"
        ));
        assert!(inbox.try_recv().is_err());
    }

    #[test]
    fn a_peer_id_no_swarm_can_make_stops_the_transport_with_a_fault() {
        let (network, outbound) = mpsc::channel(1);
        let (inbound, mut inbox) = mpsc::channel(4);
        let (swarm, wire) = mpsc::channel(4);
        swarm
            .try_send(Wire::PeerConnected(vec![0; MAX_PEER_ID_BYTES + 1]))
            .unwrap();
        swarm.try_send(Wire::PeerConnected(b"p".to_vec())).unwrap();
        drop((swarm, network));
        assert!(matches!(
            serve(&devnet(), &params(), outbound, wire, &inbound),
            Err(ComponentFault::BadPeerId(PeerIdTooLong(len))) if len == MAX_PEER_ID_BYTES + 1
        ));
        assert!(inbox.try_recv().is_err());
    }

    #[test]
    fn penalties_add_up_to_a_ban_and_a_disconnect_clears_the_score() {
        let mut scores = Scores::default();
        let peer = PeerIx(3);
        assert_eq!(
            penalize(&mut scores, peer, Misbehavior::InvalidTx),
            Standing::Tolerated
        );
        assert_eq!(
            penalize(&mut scores, peer, Misbehavior::Malformed),
            Standing::Tolerated
        );
        assert_eq!(scores.by_peer.get(&peer), Some(&-70));
        assert_eq!(
            penalize(&mut scores, peer, Misbehavior::Malformed),
            Standing::Banned
        );
        forget(&mut scores, peer);
        assert!(scores.by_peer.is_empty());
        assert_eq!(
            penalize(&mut scores, peer, Misbehavior::InvalidBlock),
            Standing::Banned
        );
    }

    #[test]
    fn a_penalty_for_a_peer_that_left_leaves_no_score() {
        let mut transport = Transport::default();
        let ix = connect(&mut transport.peers, peer()).unwrap().unwrap();
        apply_penalty(&mut transport, ix, Misbehavior::Malformed);
        assert_eq!(transport.scores.by_peer.get(&ix), Some(&-50));
        assert_eq!(disconnect(&mut transport.peers, &peer()), Some(ix));
        forget(&mut transport.scores, ix);
        apply_penalty(&mut transport, ix, Misbehavior::Malformed);
        assert!(transport.scores.by_peer.is_empty());
    }

    #[test]
    fn commands_of_the_node_do_not_stop_the_transport() {
        let (network, outbound) = mpsc::channel(8);
        let (inbound, mut inbox) = mpsc::channel(4);
        let (swarm, wire) = mpsc::channel(4);
        swarm.try_send(Wire::PeerConnected(b"p".to_vec())).unwrap();
        swarm
            .try_send(Wire::Gossip {
                topic: "/pouw/devnet/coin-txs/1".to_owned(),
                from: b"p".to_vec(),
                bytes: transfer_bytes(),
            })
            .unwrap();
        let node = std::thread::spawn(move || {
            let Some(Inbound::PeerConnected { peer, .. }) = inbox.blocking_recv() else {
                panic!("the node saw no peer");
            };
            let Some(Inbound::Gossip { id, from, message }) = inbox.blocking_recv() else {
                panic!("the node got no gossip");
            };
            assert_eq!(from, peer);
            let commands = [
                Command::Report(peer, Misbehavior::Unresponsive),
                Command::Validate {
                    id,
                    from,
                    topic: message.topic(),
                    acceptance: Acceptance::Reject,
                },
                Command::Answer {
                    id: ServeId(0),
                    response: SyncResponse::Blocks(vec![]),
                },
                Command::Broadcast(message),
            ];
            for command in commands {
                network.blocking_send(command).unwrap();
            }
            drop((swarm, network));
        });
        serve(&devnet(), &params(), outbound, wire, &inbound).unwrap();
        node.join().unwrap();
    }

    #[test]
    fn a_sync_request_reaches_the_node_and_a_rejection_is_blamed_by_topic() {
        let (inbound, mut inbox) = mpsc::channel(4);
        let request = SyncRequest::GetHeaders(Box::new(GetHeaders {
            locator: vec![],
            stop: None,
        }));
        let bytes = borsh::to_vec(&request).unwrap();
        assert!(bytes.len() <= protocol::MAX_SYNC_REQUEST_BYTES);
        let received = block_on(on_sync_request_bytes(
            PeerIx(2),
            ServeId(5),
            &bytes,
            &inbound,
        ));
        assert!(matches!(received, SyncReceived::Forwarded));
        let Ok(Inbound::Request {
            from,
            serve,
            request: got,
        }) = inbox.try_recv()
        else {
            panic!("the node got no request");
        };
        assert_eq!((from, serve, got), (PeerIx(2), ServeId(5), request));
        let long = vec![0; protocol::MAX_SYNC_REQUEST_BYTES + 1];
        for bad in [long.as_slice(), &[0xff]] {
            assert!(matches!(
                block_on(on_sync_request_bytes(PeerIx(2), ServeId(6), bad, &inbound)),
                SyncReceived::Refused(Misbehavior::Malformed)
            ));
        }
        assert!(inbox.try_recv().is_err());
        assert_eq!(rejection(Topic::BlockAnnounce), Misbehavior::InvalidBlock);
        assert_eq!(rejection(Topic::CoinTxs), Misbehavior::InvalidTx);
        assert_eq!(rejection(Topic::ProofRequests), Misbehavior::InvalidTx);
    }

    #[test]
    fn messages_round_trip_through_the_wire_form() {
        let message = Gossip::Tx(Box::new(checked_tx(TxKind::Transfer {
            to: Address([2; 32]),
            amount: Amount(1),
        })));
        let bytes = message.to_wire().unwrap();
        assert_eq!(decode(Topic::CoinTxs, &bytes).unwrap(), message);
        let request = SyncRequest::GetBlocks(GetBlocks {
            ids: vec![pouw_types::BlockId::ZERO],
        });
        let bytes = borsh::to_vec(&request).unwrap();
        assert_eq!(borsh::from_slice::<SyncRequest>(&bytes).unwrap(), request);
    }

    #[test]
    fn an_announcement_is_the_tag_and_the_raw_header() {
        let bytes = announce_bytes();
        assert_eq!(bytes.len(), ANNOUNCE_WIRE_BYTES);
        assert_eq!(ANNOUNCE_WIRE_BYTES, 169);
        let message = decode(Topic::BlockAnnounce, &bytes).unwrap();
        let Gossip::Announce(announce) = &message else {
            panic!("expected an announcement");
        };
        assert_eq!(announce.header, announce_header());
        assert_eq!(message.topic(), Topic::BlockAnnounce);
        assert_eq!(message.to_wire().unwrap(), bytes);
    }

    #[test]
    fn a_bad_announcement_is_refused_by_the_precheck() {
        let mut other_chain = announce_header();
        other_chain.chain_id = U32::new(2);
        let mut bytes = vec![ANNOUNCE_TAG];
        bytes.extend_from_slice(zerocopy::IntoBytes::as_bytes(&other_chain));
        let error = decode(Topic::BlockAnnounce, &bytes).unwrap_err();
        assert_eq!(error.misbehavior(), Misbehavior::InvalidBlock);
        let mut short = announce_bytes();
        short.pop();
        let error = decode(Topic::BlockAnnounce, &short).unwrap_err();
        assert_eq!(error.misbehavior(), Misbehavior::Malformed);
        assert!(matches!(
            decode(Topic::CoinTxs, &announce_bytes()),
            Err(GossipError::WrongTopic {
                topic: Topic::CoinTxs,
                found: Topic::BlockAnnounce,
            })
        ));
    }

    #[test]
    fn a_status_goes_to_the_node_and_a_bad_one_costs_the_peer() {
        let (inbound, mut inbox) = mpsc::channel(4);
        let (swarm, wire) = mpsc::channel(8);
        let (network_handle, outbound) = mpsc::channel(1);
        let status = protocol::Status {
            protocol_version: protocol::PROTOCOL_VERSION,
            chain_id: ChainId(1),
            genesis: pouw_types::BlockId::ZERO,
            tip: pouw_types::BlockId::ZERO,
            height: pouw_types::Height(0),
            cumulative_work: pouw_types::CumWork(pouw_types::U256::from(1_u64)),
            services: protocol::Services::ARCHIVE,
            agent: "test".to_owned(),
        };
        let good = protocol::encode_status(&status).unwrap();
        let unknown = Wire::Status {
            from: b"s".to_vec(),
            bytes: good.clone(),
        };
        for message in [
            Wire::PeerConnected(b"p".to_vec()),
            Wire::Status {
                from: b"p".to_vec(),
                bytes: good,
            },
            Wire::Status {
                from: b"p".to_vec(),
                bytes: vec![1, 2, 3],
            },
            unknown,
        ] {
            swarm.try_send(message).unwrap();
        }
        drop((swarm, network_handle));
        serve(&devnet(), &params(), outbound, wire, &inbound).unwrap();
        assert!(matches!(
            inbox.try_recv(),
            Ok(Inbound::PeerConnected { .. })
        ));
        let Ok(Inbound::Status { from, status: got }) = inbox.try_recv() else {
            panic!("the node got no status");
        };
        assert_eq!((from, *got), (PeerIx(0), status));
        assert!(inbox.try_recv().is_err());
    }

    #[test]
    fn a_sync_answer_is_prechecked_before_the_node() {
        let (inbound, mut inbox) = mpsc::channel(4);
        let (swarm, wire) = mpsc::channel(4);
        let (network_handle, outbound) = mpsc::channel(1);
        let answer = borsh::to_vec(&SyncResponse::Headers(vec![announce_header()])).unwrap();
        for bytes in [answer, vec![0xff]] {
            swarm
                .try_send(Wire::SyncResponse {
                    id: RequestId(4),
                    bytes,
                })
                .unwrap();
        }
        drop((swarm, network_handle));
        serve(&devnet(), &params(), outbound, wire, &inbound).unwrap();
        assert!(matches!(
            inbox.try_recv(),
            Ok(Inbound::Response {
                id: RequestId(4),
                result: Ok(Fetched::Headers(_)),
            })
        ));
        assert!(matches!(
            inbox.try_recv(),
            Ok(Inbound::Response {
                id: RequestId(4),
                result: Err(NetworkError::BadAnswer(Misbehavior::Malformed)),
            })
        ));
    }

    #[test]
    fn misbehavior_penalties_are_the_limits_constants() {
        assert_eq!(Misbehavior::Malformed.penalty(), 50);
        assert_eq!(Misbehavior::InvalidBlock.penalty(), 100);
        assert_eq!(Misbehavior::InvalidTx.penalty(), 20);
        assert_eq!(Misbehavior::Unresponsive.penalty(), 10);
        assert_eq!(BAN_SCORE, -100);
    }
}
