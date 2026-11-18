//! The libp2p swarm of the node, first part of pouw-node#85: the identity of the node,
//! the connections to the bootnodes and the discovery of other peers.
//!
//! The swarm runs on its own thread with its own tokio runtime and speaks to the
//! transport thread only through the wire channel ([`Wire`]): it reports a peer with
//! [`Wire::PeerConnected`] once the peer proved to be on the same network, and with
//! [`Wire::PeerDisconnected`] when the last connection to it is gone. The node never
//! sees a libp2p type.
//!
//! The stack: TCP, Noise for encryption, Yamux for multiplexing and DNS names in
//! addresses. On top of it:
//! - identify: a peer tells the other its listen addresses and its
//!   [`protocol_id`](super::protocol::protocol_id) of `identify`, which names the
//!   network. A peer of another network is disconnected and never reported.
//! - Kademlia, under a protocol name of this network, with the bootnodes as first
//!   entries. It is the peer list: a bootstrap query asks known peers for the peers
//!   near the node, so peers that only know one bootnode find each other.
//!
//! - gossipsub (pouw-node#86), on the topics of [`subscriptions`]. A message that arrives
//!   goes to the transport as [`Wire::Gossip`] under a number the swarm gives it, and is
//!   relayed to other peers only after the verdict of the node comes back as
//!   [`ToSwarm::Verdict`] of that number; until then it waits in a table of at most
//!   `MAX_PENDING` entries, and a message that waits more than `PENDING_TTL` is
//!   ignored. [`ToSwarm::Publish`] sends a message of the node to the peers of its topic.
//!
//! The channel is bounded and the swarm waits for a free slot before it reads the
//! sockets again, as the module doc of [`p2p`](super) describes.
//!
//! - request-response, one protocol for `status` and one for `sync`, both with the frames
//!   of `frames`. A `Status` is a request with an empty answer, sent once
//!   by each side. A `sync` request goes to the transport as [`Wire::SyncRequest`] under a
//!   number of the swarm, which holds the response channel of the request in a table until
//!   the transport answers with [`ToSwarm::Answer`] or [`ToSwarm::Drop`]. A request of
//!   the node ([`ToSwarm::Request`]) comes back as [`Wire::SyncResponse`] or, when it
//!   fails or times out, as [`Wire::RequestFailed`]. A peer that sends a request is
//!   reported as connected before the request is forwarded, because it may arrive before
//!   the identify exchange is over: the protocol ids carry the network, so a peer that
//!   speaks them is on this one.
//!
//! The transport commands the swarm with [`ToSwarm`] on a second channel, which the
//! transport fills with `try_send` and never waits on.
//!
//! Not built yet, each is a part of a later task: the connection limits of
//! [`PeerLimits`](super::PeerLimits) and the ban list.

use std::time::{Duration, Instant};
use std::{
    collections::{HashMap, HashSet},
    io,
    num::NonZeroUsize,
    sync::mpsc as std_mpsc,
    thread,
};

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder, TransportError,
    gossipsub::{self, IdentTopic, MessageAcceptance},
    identify,
    identity::Keypair,
    kad,
    multiaddr::Protocol,
    noise,
    request_response::{
        self, InboundRequestId, OutboundFailure, OutboundRequestId, ProtocolSupport,
        ResponseChannel,
    },
    swarm::{InvalidProtocol, NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use pouw_types::NetworkName;
use thiserror::Error;
use tokio::{
    runtime,
    sync::mpsc,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};

use super::{
    Acceptance, MessageId, NetworkError, RequestId, SWARM_COMMAND_CAPACITY, ServeId, SwarmIn,
    ToSwarm, TransportConfig, TransportFailure, WIRE_CAPACITY, Wire, WireIn,
    frames::FrameCodec,
    identity::{self, IdentityError},
    protocol, subscriptions,
};

/// Name of the identify protocol in a protocol id. The protocol id is also the
/// `protocol_version` a peer announces, which is how two networks tell each other apart.
const IDENTIFY: &str = "identify";

/// Name of the Kademlia protocol in a protocol id.
const KADEMLIA: &str = "kad";

/// How often the swarm dials the bootnodes again while it has no peer, so a bootnode that
/// starts later is found.
const REDIAL_INTERVAL: Duration = Duration::from_secs(10);

/// How long a connection that no protocol uses stays open. Only the gossip and sync
/// protocols of the next tasks keep a connection busy, until then a long timeout keeps
/// the peers connected.
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_hours(1);

/// How many gossip messages may wait for the verdict of the node at once. A message that
/// arrives beyond it is ignored at once, so a peer cannot make the swarm hold more.
const MAX_PENDING: usize = 1024;

/// How long a gossip message waits for its verdict. After that it is ignored: the node
/// dropped the verdict, the transport could not pass it on, or the message never reached
/// the node.
const PENDING_TTL: Duration = Duration::from_secs(30);

/// How often the swarm looks for gossip messages that wait too long.
const SWEEP_INTERVAL: Duration = Duration::from_secs(5);

/// How long a `Status` waits for the empty answer that completes it.
const STATUS_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a sync request waits for its answer, which may hold sixteen blocks.
const SYNC_TIMEOUT: Duration = Duration::from_secs(60);

/// Why the swarm cannot start. Each is a fault of this node or of its configuration,
/// never of a peer.
#[derive(Debug, Error)]
pub enum SwarmError {
    #[error(transparent)]
    Identity(#[from] IdentityError),
    #[error("cannot start the swarm thread: {0}")]
    Thread(#[source] io::Error),
    #[error("cannot start the swarm runtime: {0}")]
    Runtime(#[source] io::Error),
    #[error("a Kademlia bucket needs at least one entry")]
    BucketSize,
    #[error("{name:?} is not a protocol name: {source}")]
    ProtocolName {
        name: String,
        #[source]
        source: InvalidProtocol,
    },
    #[error("cannot set up the encryption: {0}")]
    Noise(#[from] noise::Error),
    #[error("cannot set up the DNS resolver: {0}")]
    Dns(#[source] io::Error),
    #[error("{addr:?} is not a multiaddr: {source}")]
    Address {
        addr: String,
        #[source]
        source: libp2p::multiaddr::Error,
    },
    #[error("cannot listen on {addr}: {source}")]
    Listen {
        addr: Multiaddr,
        #[source]
        source: TransportError<io::Error>,
    },
    #[error("cannot set up gossipsub: {0}")]
    Gossipsub(String),
    #[error("the swarm thread ended before it was ready")]
    Gone,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// `Status`, once per connection and side: the request is the status, the answer is
    /// empty.
    status: request_response::Behaviour<FrameCodec>,
    /// `SyncRequest` and `SyncResponse`.
    sync: request_response::Behaviour<FrameCodec>,
    /// The messages of the topics of [`subscriptions`].
    gossipsub: gossipsub::Behaviour,
}

/// A gossip message that waits for the verdict of the node.
#[derive(Debug)]
struct Pending {
    /// The id gossipsub knows the message by.
    id: gossipsub::MessageId,
    /// The peer that sent it to us, which gossipsub needs to apply the verdict.
    source: PeerId,
    since: Instant,
}

/// What the swarm remembers between events.
#[derive(Debug, Default)]
struct Book {
    /// The peers the node was told about, so a disconnect is reported only for them. Holds
    /// at most the connected peers.
    reported: HashSet<PeerId>,
    /// Whether the one bootstrap query of this run was started.
    bootstrapped: bool,
    /// The id of the next sync request handed to the transport.
    next_serve: u64,
    /// The sync requests of peers that wait for the answer of the node, by the number the
    /// transport knows them by.
    serving: HashMap<ServeId, Served>,
    /// The same requests by their libp2p id, to find one that fails.
    served_by: HashMap<InboundRequestId, ServeId>,
    /// The sync requests of the node that wait for an answer.
    asked: HashMap<OutboundRequestId, RequestId>,
    /// The gossip messages that wait for a verdict, by the number the node knows them by.
    /// Holds at most [`MAX_PENDING`] entries.
    pending: HashMap<u64, Pending>,
    /// The number of the next gossip message handed to the transport.
    next_message: u64,
}

/// A sync request of a peer and the channel its answer goes back on.
#[derive(Debug)]
struct Served {
    peer: PeerId,
    request: InboundRequestId,
    channel: ResponseChannel<Vec<u8>>,
}

impl Book {
    /// Forgets the requests of a peer whose last connection closed: nothing can answer them.
    fn forget_peer(&mut self, peer: &PeerId) {
        self.serving.retain(|_, served| served.peer != *peer);
        let serving = &self.serving;
        self.served_by.retain(|_, id| serving.contains_key(id));
    }
}

/// Starts the swarm on its own thread and returns the channel it feeds. Returns when the
/// swarm listens on at least one address of `config.listen`: an address the host cannot
/// serve (IPv6 inside a container without it) is logged and skipped, but a node that
/// cannot listen anywhere is an error here and not a silent node without peers.
pub fn start(config: &TransportConfig) -> Result<(WireIn, SwarmIn), SwarmError> {
    let keypair = identity::load_or_create(&config.data_dir)?;
    let (wire, wire_in) = mpsc::channel(WIRE_CAPACITY);
    let (to_swarm, commands) = mpsc::channel(SWARM_COMMAND_CAPACITY);
    let (ready, ready_in) = std_mpsc::sync_channel(1);
    let config = config.clone();
    thread::Builder::new()
        .name("Swarm".to_owned())
        .spawn(move || run(&config, keypair, &wire, commands, &ready))
        .map_err(SwarmError::Thread)?;
    match ready_in.recv() {
        Ok(Ok(())) => Ok((wire_in, to_swarm)),
        Ok(Err(error)) => Err(error),
        Err(std_mpsc::RecvError) => Err(SwarmError::Gone),
    }
}

/// The body of the swarm thread. `ready` carries the outcome of the setup, once.
fn run(
    config: &TransportConfig,
    keypair: Keypair,
    wire: &mpsc::Sender<Wire>,
    commands: mpsc::Receiver<ToSwarm>,
    ready: &std_mpsc::SyncSender<Result<(), SwarmError>>,
) {
    let runtime = match runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            tell(ready, Err(SwarmError::Runtime(error)));
            return;
        }
    };
    runtime.block_on(async {
        let (swarm, bootnodes) = match setup(config, keypair) {
            Ok(set_up) => set_up,
            Err(error) => {
                tell(ready, Err(error));
                return;
            }
        };
        tell(ready, Ok(()));
        let version = protocol::protocol_id(&config.network, IDENTIFY);
        drive(swarm, &bootnodes, &version, wire, commands).await;
    });
}

fn tell(ready: &std_mpsc::SyncSender<Result<(), SwarmError>>, outcome: Result<(), SwarmError>) {
    if ready.send(outcome).is_err() {
        debug!("nobody waits for the swarm any more");
    }
}

/// Builds the swarm, starts the listeners and puts the bootnodes that name their peer in
/// the routing table. Returns the swarm and the bootnode addresses to dial.
fn setup(
    config: &TransportConfig,
    keypair: Keypair,
) -> Result<(Swarm<Behaviour>, Vec<Multiaddr>), SwarmError> {
    let local = keypair.public().to_peer_id();
    info!(peer_id = %local, "libp2p identity");
    let mut swarm = build(config, keypair)?;
    let mut listening = false;
    let mut first_failure = None;
    for text in &config.listen {
        let addr = parse(text)?;
        match swarm.listen_on(addr.clone()) {
            Ok(_) => listening = true,
            Err(source) => {
                warn!(%addr, %source, "cannot listen");
                first_failure.get_or_insert(SwarmError::Listen { addr, source });
            }
        }
    }
    if let (false, Some(failure)) = (listening, first_failure) {
        return Err(failure);
    }
    let mut bootnodes = Vec::with_capacity(config.bootnodes.len());
    for text in &config.bootnodes {
        let addr = parse(text)?;
        if let Some((peer, base)) = split_peer(&addr) {
            let update = swarm.behaviour_mut().kademlia.add_address(&peer, base);
            debug!(%peer, ?update, "bootnode in the routing table");
        }
        bootnodes.push(addr);
    }
    Ok((swarm, bootnodes))
}

fn build(config: &TransportConfig, keypair: Keypair) -> Result<Swarm<Behaviour>, SwarmError> {
    let version = protocol::protocol_id(&config.network, IDENTIFY);
    let name = protocol::protocol_id(&config.network, KADEMLIA);
    let kademlia_protocol = StreamProtocol::try_from_owned(name.clone())
        .map_err(|source| SwarmError::ProtocolName { name, source })?;
    let status_protocol = stream_protocol(&config.network, protocol::STATUS)?;
    let sync_protocol = stream_protocol(&config.network, protocol::SYNC)?;
    let bucket =
        NonZeroUsize::new(config.limits.kademlia_bucket_size).ok_or(SwarmError::BucketSize)?;
    let gossipsub = build_gossipsub(config, &keypair)?;
    let agent = format!("pouw-node/{}", env!("CARGO_PKG_VERSION"));
    let Ok(builder) = SwarmBuilder::with_existing_identity(keypair)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_dns()
        .map_err(SwarmError::Dns)?
        .with_behaviour(|key| {
            let local = key.public().to_peer_id();
            let mut kademlia_config = kad::Config::new(kademlia_protocol);
            kademlia_config.set_kbucket_size(bucket);
            let store = kad::store::MemoryStore::new(local);
            let mut kademlia = kad::Behaviour::with_config(local, store, kademlia_config);
            // A node answers queries of its peers whether or not it knows an address
            // other nodes can reach it on, which behind Docker it does not.
            kademlia.set_mode(Some(kad::Mode::Server));
            let identify_config =
                identify::Config::new(version, key.public()).with_agent_version(agent);
            let status_codec = FrameCodec {
                max_request: protocol::MAX_STATUS_BYTES,
                max_response: 0,
            };
            let sync_codec = FrameCodec {
                max_request: protocol::MAX_SYNC_REQUEST_BYTES,
                max_response: protocol::MAX_RESPONSE_BYTES,
            };
            let status_config =
                request_response::Config::default().with_request_timeout(STATUS_TIMEOUT);
            let sync_config =
                request_response::Config::default().with_request_timeout(SYNC_TIMEOUT);
            Behaviour {
                identify: identify::Behaviour::new(identify_config),
                kademlia,
                status: request_response::Behaviour::with_codec(
                    status_codec,
                    [(status_protocol, ProtocolSupport::Full)],
                    status_config,
                ),
                sync: request_response::Behaviour::with_codec(
                    sync_codec,
                    [(sync_protocol, ProtocolSupport::Full)],
                    sync_config,
                ),
                gossipsub,
            }
        });
    Ok(builder
        .with_swarm_config(|config| config.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build())
}

/// Gossipsub with the topics of [`subscriptions`], subscribed. The mesh degree is
/// [`PeerLimits::mesh_d`](super::PeerLimits). Messages are signed and checked strictly,
/// and `validate_messages` holds each received message back until the node's verdict.
/// The size limit is the largest of the topics; the precheck of the transport enforces
/// the limit of each topic.
fn build_gossipsub(
    config: &TransportConfig,
    keypair: &Keypair,
) -> Result<gossipsub::Behaviour, SwarmError> {
    let topics = subscriptions(&config.network);
    let largest = topics
        .iter()
        .map(|subscription| subscription.max_transmit_size)
        .max()
        .unwrap_or(0);
    let mesh = usize::try_from(config.limits.mesh_d)
        .map_err(|error| SwarmError::Gossipsub(error.to_string()))?;
    let gossip_config = gossipsub::ConfigBuilder::default()
        .validation_mode(gossipsub::ValidationMode::Strict)
        .validate_messages()
        .mesh_n(mesh)
        .max_transmit_size(largest)
        .build()
        .map_err(|error| SwarmError::Gossipsub(error.to_string()))?;
    let mut behaviour = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(keypair.clone()),
        gossip_config,
    )
    .map_err(|error| SwarmError::Gossipsub(error.to_string()))?;
    for subscription in &topics {
        behaviour
            .subscribe(&IdentTopic::new(subscription.id.clone()))
            .map_err(|error| SwarmError::Gossipsub(error.to_string()))?;
    }
    Ok(behaviour)
}

/// The libp2p name of the protocol `name` on `network`.
fn stream_protocol(network: &NetworkName, name: &str) -> Result<StreamProtocol, SwarmError> {
    let id = protocol::protocol_id(network, name);
    StreamProtocol::try_from_owned(id.clone())
        .map_err(|source| SwarmError::ProtocolName { name: id, source })
}

fn parse(text: &str) -> Result<Multiaddr, SwarmError> {
    text.parse().map_err(|source| SwarmError::Address {
        addr: text.to_owned(),
        source,
    })
}

/// The peer id and the rest of an address that ends in `/p2p/<id>`.
fn split_peer(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut base = addr.clone();
    match base.pop() {
        Some(Protocol::P2p(peer)) => Some((peer, base)),
        _ => None,
    }
}

/// Handles the swarm events and the commands of the transport until the transport thread
/// is gone. Dials the bootnodes at once and again every [`REDIAL_INTERVAL`] while no peer
/// is connected, and every [`SWEEP_INTERVAL`] ignores the gossip messages that wait too
/// long for a verdict.
async fn drive(
    mut swarm: Swarm<Behaviour>,
    bootnodes: &[Multiaddr],
    version: &str,
    wire: &mpsc::Sender<Wire>,
    mut commands: mpsc::Receiver<ToSwarm>,
) {
    let mut book = Book::default();
    let mut redial = time::interval(REDIAL_INTERVAL);
    redial.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let mut sweep = time::interval(SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                if !on_event(&mut swarm, &mut book, version, event, wire).await {
                    return;
                }
            }
            command = commands.recv() => {
                let Some(command) = command else {
                    info!("the transport is gone, the swarm stops");
                    return;
                };
                if !on_command(&mut swarm, &mut book, command, wire).await {
                    return;
                }
            }
            _ = redial.tick() => dial_bootnodes(&mut swarm, bootnodes),
            _ = sweep.tick() => expire(&mut swarm, &mut book),
        }
    }
}

fn dial_bootnodes(swarm: &mut Swarm<Behaviour>, bootnodes: &[Multiaddr]) {
    if swarm.connected_peers().next().is_some() {
        return;
    }
    for addr in bootnodes {
        match swarm.dial(addr.clone()) {
            Ok(()) => debug!(%addr, "dialing a bootnode"),
            Err(error) => warn!(%addr, %error, "cannot dial a bootnode"),
        }
    }
}

/// Handles one event. `false` means the transport thread is gone and the swarm stops.
async fn on_event(
    swarm: &mut Swarm<Behaviour>,
    book: &mut Book,
    version: &str,
    event: SwarmEvent<BehaviourEvent>,
    wire: &mpsc::Sender<Wire>,
) -> bool {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => info!(%address, "listening"),
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            debug!(?peer_id, %error, "outgoing connection failed");
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established: 0,
            cause,
            ..
        } => {
            debug!(%peer_id, ?cause, "last connection closed");
            book.forget_peer(&peer_id);
            if book.reported.remove(&peer_id) {
                info!(%peer_id, "peer disconnected");
                return send(wire, Wire::PeerDisconnected(peer_id.to_bytes())).await;
            }
        }
        SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
            peer_id,
            info,
            ..
        })) => return on_identified(swarm, book, version, peer_id, info, wire).await,
        SwarmEvent::Behaviour(BehaviourEvent::Kademlia(kad::Event::RoutingUpdated {
            peer,
            is_new_peer,
            ..
        })) => debug!(%peer, is_new_peer, "routing table updated"),
        SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        })) => {
            return on_gossip(swarm, book, propagation_source, message_id, message, wire).await;
        }
        SwarmEvent::Behaviour(BehaviourEvent::Status(event)) => {
            return on_status(swarm, book, event, wire).await;
        }
        SwarmEvent::Behaviour(BehaviourEvent::Sync(event)) => {
            return on_sync(book, event, wire).await;
        }
        _ => {}
    }
    true
}

/// A gossip message arrived. It waits in the book under a new number, and the transport
/// gets it as [`Wire::Gossip`]; gossipsub relays it after the verdict of the node. Beyond
/// [`MAX_PENDING`] waiting messages a new one is ignored at once.
async fn on_gossip(
    swarm: &mut Swarm<Behaviour>,
    book: &mut Book,
    source: PeerId,
    id: gossipsub::MessageId,
    message: gossipsub::Message,
    wire: &mpsc::Sender<Wire>,
) -> bool {
    let pending = Pending {
        id,
        source,
        since: Instant::now(),
    };
    if book.pending.len() >= MAX_PENDING {
        warn!(%source, "too many gossip messages wait for a verdict, ignoring one");
        report(swarm, &pending, MessageAcceptance::Ignore);
        return true;
    }
    if !report_peer(book, source, wire).await {
        return false;
    }
    let number = book.next_message;
    book.next_message = number.wrapping_add(1);
    book.pending.insert(number, pending);
    let message = Wire::Gossip {
        id: MessageId(number),
        topic: message.topic.into_string(),
        from: source.to_bytes(),
        bytes: message.data,
    };
    send(wire, message).await
}

/// Tells gossipsub what to do with a message that waited for a verdict: relay it
/// (`Accept`), drop it (`Ignore`), or drop it and lower the score of its sender (`Reject`).
fn report(swarm: &mut Swarm<Behaviour>, pending: &Pending, acceptance: MessageAcceptance) {
    let outcome = swarm
        .behaviour_mut()
        .gossipsub
        .report_message_validation_result(&pending.id, &pending.source, acceptance);
    debug!(?outcome, id = %pending.id, "verdict passed to gossipsub");
}

/// Ignores the gossip messages that wait longer than [`PENDING_TTL`] for a verdict, which
/// frees their slots.
fn expire(swarm: &mut Swarm<Behaviour>, book: &mut Book) {
    let stale: Vec<u64> = book
        .pending
        .iter()
        .filter(|(_, pending)| pending.since.elapsed() > PENDING_TTL)
        .map(|(number, _)| *number)
        .collect();
    for number in stale {
        if let Some(pending) = book.pending.remove(&number) {
            warn!(
                number,
                "no verdict on a gossip message in time, ignoring it"
            );
            report(swarm, &pending, MessageAcceptance::Ignore);
        }
    }
}

/// A peer told us who it is. A peer of another network is disconnected. A peer of this
/// network gives Kademlia its addresses, starts the bootstrap query the first time, and
/// is reported to the node the first time.
async fn on_identified(
    swarm: &mut Swarm<Behaviour>,
    book: &mut Book,
    version: &str,
    peer_id: PeerId,
    info: identify::Info,
    wire: &mpsc::Sender<Wire>,
) -> bool {
    if info.protocol_version != version {
        debug!(%peer_id, theirs = %info.protocol_version, "peer of another network");
        if swarm.disconnect_peer_id(peer_id).is_err() {
            debug!(%peer_id, "no connection to close");
        }
        return true;
    }
    for address in info.listen_addrs {
        let update = swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, address);
        debug!(%peer_id, ?update, "address of a peer");
    }
    if !book.bootstrapped {
        match swarm.behaviour_mut().kademlia.bootstrap() {
            Ok(query) => {
                book.bootstrapped = true;
                debug!(?query, "bootstrap started");
            }
            Err(error) => debug!(%error, "no bootstrap yet"),
        }
    }
    if book.reported.insert(peer_id) {
        info!(%peer_id, agent = %info.agent_version, "peer connected");
        return send(wire, Wire::PeerConnected(peer_id.to_bytes())).await;
    }
    true
}

/// Reports `peer` to the transport if it was not yet. A peer can send a request before the
/// identify exchange is over, and the transport drops what comes from a peer it does not
/// know. The protocol ids carry the network, so a peer that gets this far is on ours.
async fn report_peer(book: &mut Book, peer: PeerId, wire: &mpsc::Sender<Wire>) -> bool {
    if book.reported.insert(peer) {
        info!(%peer, "peer connected");
        return send(wire, Wire::PeerConnected(peer.to_bytes())).await;
    }
    true
}

/// Handles one command of the transport. `false` means the transport thread is gone.
async fn on_command(
    swarm: &mut Swarm<Behaviour>,
    book: &mut Book,
    command: ToSwarm,
    wire: &mpsc::Sender<Wire>,
) -> bool {
    match command {
        ToSwarm::Request { id, peer, bytes } => {
            let Ok(peer) = PeerId::from_bytes(&peer) else {
                let error = NetworkError::Transport(TransportFailure::DialFailure);
                return send(wire, Wire::RequestFailed { id, error }).await;
            };
            let asked = swarm.behaviour_mut().sync.send_request(&peer, bytes);
            book.asked.insert(asked, id);
        }
        ToSwarm::Answer { id, bytes } => {
            if let Some(served) = book.serving.remove(&id) {
                book.served_by.remove(&served.request);
                if swarm
                    .behaviour_mut()
                    .sync
                    .send_response(served.channel, bytes)
                    .is_err()
                {
                    debug!(?id, "the peer is gone, the answer is dropped");
                }
            } else {
                debug!(?id, "an answer to a request that is gone");
            }
        }
        ToSwarm::Drop { id } => {
            if let Some(served) = book.serving.remove(&id) {
                book.served_by.remove(&served.request);
                debug!(?id, peer = %served.peer, "a request is left unanswered");
            }
        }
        ToSwarm::Status { peer, bytes } => match PeerId::from_bytes(&peer) {
            Ok(peer) => {
                swarm.behaviour_mut().status.send_request(&peer, bytes);
            }
            Err(error) => debug!(%error, "a status for a peer id that does not parse"),
        },
        ToSwarm::Publish { topic, bytes } => {
            match swarm
                .behaviour_mut()
                .gossipsub
                .publish(IdentTopic::new(topic), bytes)
            {
                Ok(id) => debug!(%id, "gossip message published"),
                Err(error) => debug!(%error, "gossip message not published"),
            }
        }
        ToSwarm::Verdict { id, acceptance } => {
            let Some(pending) = book.pending.remove(&id.0) else {
                debug!(?id, "verdict on a gossip message that is not waiting");
                return true;
            };
            let acceptance = match acceptance {
                Acceptance::Accept => MessageAcceptance::Accept,
                Acceptance::Ignore => MessageAcceptance::Ignore,
                Acceptance::Reject => MessageAcceptance::Reject,
            };
            report(swarm, &pending, acceptance);
        }
        ToSwarm::Disconnect { peer } => match PeerId::from_bytes(&peer) {
            Ok(peer) => {
                if swarm.disconnect_peer_id(peer).is_err() {
                    debug!(%peer, "no connection to close");
                }
            }
            Err(error) => debug!(%error, "a disconnect for a peer id that does not parse"),
        },
    }
    true
}

/// Handles an event of the `status` protocol: the status of a peer is acknowledged with
/// an empty answer and handed to the transport. What happens to our own status, an
/// answer or a failure, is only logged: the node sends it once and does not wait for it.
async fn on_status(
    swarm: &mut Swarm<Behaviour>,
    book: &mut Book,
    event: request_response::Event<Vec<u8>, Vec<u8>>,
    wire: &mpsc::Sender<Wire>,
) -> bool {
    match event {
        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request, channel, ..
                },
            ..
        } => {
            if swarm
                .behaviour_mut()
                .status
                .send_response(channel, Vec::new())
                .is_err()
            {
                debug!(%peer, "the peer left before its status was acknowledged");
            }
            if !report_peer(book, peer, wire).await {
                return false;
            }
            return send(
                wire,
                Wire::Status {
                    from: peer.to_bytes(),
                    bytes: request,
                },
            )
            .await;
        }
        request_response::Event::OutboundFailure { peer, error, .. } => {
            debug!(%peer, %error, "our status was not delivered");
        }
        request_response::Event::InboundFailure { peer, error, .. } => {
            debug!(%peer, %error, "a status could not be acknowledged");
        }
        _ => {}
    }
    true
}

/// Handles an event of the `sync` protocol.
async fn on_sync(
    book: &mut Book,
    event: request_response::Event<Vec<u8>, Vec<u8>>,
    wire: &mpsc::Sender<Wire>,
) -> bool {
    match event {
        request_response::Event::Message {
            peer,
            message:
                request_response::Message::Request {
                    request_id,
                    request,
                    channel,
                },
            ..
        } => {
            if !report_peer(book, peer, wire).await {
                return false;
            }
            let id = ServeId(book.next_serve);
            book.next_serve = book.next_serve.wrapping_add(1);
            let served = Served {
                peer,
                request: request_id,
                channel,
            };
            book.serving.insert(id, served);
            book.served_by.insert(request_id, id);
            return send(
                wire,
                Wire::SyncRequest {
                    id,
                    from: peer.to_bytes(),
                    bytes: request,
                },
            )
            .await;
        }
        request_response::Event::Message {
            message:
                request_response::Message::Response {
                    request_id,
                    response,
                },
            ..
        } => {
            if let Some(id) = book.asked.remove(&request_id) {
                return send(
                    wire,
                    Wire::SyncResponse {
                        id,
                        bytes: response,
                    },
                )
                .await;
            }
        }
        request_response::Event::OutboundFailure {
            request_id, error, ..
        } => {
            if let Some(id) = book.asked.remove(&request_id) {
                debug!(?id, %error, "a sync request failed");
                let error = network_error(error);
                return send(wire, Wire::RequestFailed { id, error }).await;
            }
        }
        request_response::Event::InboundFailure {
            request_id, error, ..
        } => {
            debug!(%error, "a sync request cannot be answered");
            if let Some(id) = book.served_by.remove(&request_id) {
                book.serving.remove(&id);
            }
        }
        _ => {}
    }
    true
}

/// The error of the node for a request that failed in libp2p, one to one.
fn network_error(failure: OutboundFailure) -> NetworkError {
    match failure {
        OutboundFailure::Timeout => NetworkError::Timeout,
        OutboundFailure::DialFailure => NetworkError::Transport(TransportFailure::DialFailure),
        OutboundFailure::ConnectionClosed => {
            NetworkError::Transport(TransportFailure::ConnectionClosed)
        }
        OutboundFailure::UnsupportedProtocols => {
            NetworkError::Transport(TransportFailure::UnsupportedProtocols)
        }
        OutboundFailure::Io(error) => NetworkError::Transport(TransportFailure::Io(error.kind())),
    }
}

/// Hands a message to the transport thread, waiting while its channel is full. That wait
/// is the backpressure of the swarm: it reads no socket meanwhile.
async fn send(wire: &mpsc::Sender<Wire>, message: Wire) -> bool {
    if wire.send(message).await.is_err() {
        info!("the transport is gone, the swarm stops");
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use std::{fs, net::TcpListener, path::PathBuf, time::Instant};

    use super::*;
    use pouw_types::NetworkName;

    use crate::p2p::PeerLimits;

    /// A port nothing listens on at the moment.
    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    struct Node {
        peer: PeerId,
        wire: WireIn,
        commands: SwarmIn,
        addr: String,
        dir: PathBuf,
    }

    fn start_node(test: &str, name: &str, network: &str, bootnodes: Vec<String>) -> Node {
        let dir =
            std::env::temp_dir().join(format!("pouw-swarm-{}-{test}-{name}", std::process::id()));
        drop(fs::remove_dir_all(&dir));
        let port = free_port();
        let config = TransportConfig {
            network: NetworkName::try_from(network.to_owned()).unwrap(),
            listen: vec![format!("/ip4/127.0.0.1/tcp/{port}")],
            bootnodes,
            limits: PeerLimits::default(),
            data_dir: dir.clone(),
        };
        let (wire, commands) = start(&config).unwrap();
        let peer = identity::load_or_create(&dir)
            .unwrap()
            .public()
            .to_peer_id();
        Node {
            peer,
            wire,
            commands,
            addr: format!("/ip4/127.0.0.1/tcp/{port}"),
            dir,
        }
    }

    /// The peers a node reports within `time`, in the order of their messages.
    fn connected_within(node: &mut Node, time: Duration, want: usize) -> Vec<PeerId> {
        let runtime = runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let start = Instant::now();
        let mut peers = Vec::new();
        while peers.len() < want {
            let left = time.saturating_sub(start.elapsed());
            let next = runtime.block_on(async { time::timeout(left, node.wire.recv()).await });
            match next {
                Ok(Some(Wire::PeerConnected(bytes))) => {
                    peers.push(PeerId::from_bytes(&bytes).unwrap());
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => break,
            }
        }
        peers
    }

    /// The first message `pick` takes among those a node hands to the transport within
    /// `time`.
    fn wire_within<T>(
        node: &mut Node,
        time: Duration,
        mut pick: impl FnMut(Wire) -> Option<T>,
    ) -> Option<T> {
        let runtime = runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let start = Instant::now();
        loop {
            let left = time.saturating_sub(start.elapsed());
            match runtime.block_on(async { time::timeout(left, node.wire.recv()).await }) {
                Ok(Some(message)) => {
                    if let Some(found) = pick(message) {
                        return Some(found);
                    }
                }
                Ok(None) | Err(_) => return None,
            }
        }
    }

    /// Two nodes on one network that have reported each other.
    fn connected_pair(test: &str) -> (Node, Node) {
        let mut a = start_node(test, "a", "devnet", vec![]);
        let mut b = start_node(test, "b", "devnet", vec![a.addr.clone()]);
        assert_eq!(
            connected_within(&mut b, Duration::from_secs(20), 1),
            [a.peer]
        );
        assert_eq!(
            connected_within(&mut a, Duration::from_secs(20), 1),
            [b.peer]
        );
        (a, b)
    }

    fn clean(nodes: &[&Node]) {
        for node in nodes {
            drop(fs::remove_dir_all(&node.dir));
        }
    }

    #[test]
    fn a_node_dials_its_bootnode_and_both_report_each_other() {
        let mut a = start_node("pair", "a", "devnet", vec![]);
        let mut b = start_node("pair", "b", "devnet", vec![a.addr.clone()]);
        let seen_by_b = connected_within(&mut b, Duration::from_secs(20), 1);
        let seen_by_a = connected_within(&mut a, Duration::from_secs(20), 1);
        assert_eq!(seen_by_b, [a.peer]);
        assert_eq!(seen_by_a, [b.peer]);
        clean(&[&a, &b]);
    }

    const WAIT: Duration = Duration::from_secs(20);

    fn coin_txs_topic() -> String {
        protocol::protocol_id(
            &NetworkName::try_from("devnet".to_owned()).unwrap(),
            crate::p2p::Topic::CoinTxs.name(),
        )
    }

    /// Publishes `payload` on `topic` from `from` until `to` receives it. The peers learn
    /// each other's subscriptions a moment after they connect, and a message published
    /// before that reaches nobody, so it is published again until one arrives.
    fn publish_until_received(
        from: &Node,
        to: &mut Node,
        topic: &str,
        payload: &[u8],
    ) -> (MessageId, String, Vec<u8>, Vec<u8>) {
        for _ in 0..40 {
            let publish = ToSwarm::Publish {
                topic: topic.to_owned(),
                bytes: payload.to_vec(),
            };
            from.commands.try_send(publish).unwrap();
            let got = wire_within(to, Duration::from_millis(500), |message| match message {
                Wire::Gossip {
                    id,
                    topic,
                    from,
                    bytes,
                } => Some((id, topic, from, bytes)),
                _ => None,
            });
            if let Some(got) = got {
                return got;
            }
        }
        panic!("the message did not arrive");
    }

    #[test]
    fn a_published_message_reaches_the_peer_and_waits_for_its_verdict() {
        let (a, mut b) = connected_pair("gossip");
        let topic = coin_txs_topic();
        let payload = b"a transaction".to_vec();
        let (id, got_topic, from, bytes) = publish_until_received(&a, &mut b, &topic, &payload);
        assert_eq!(got_topic, topic);
        assert_eq!(from, a.peer.to_bytes());
        assert_eq!(bytes, payload);
        b.commands
            .try_send(ToSwarm::Verdict {
                id,
                acceptance: Acceptance::Accept,
            })
            .unwrap();
        // a verdict on a number that is not waiting changes nothing
        b.commands
            .try_send(ToSwarm::Verdict {
                id: MessageId(u64::MAX),
                acceptance: Acceptance::Reject,
            })
            .unwrap();
        clean(&[&a, &b]);
    }

    #[test]
    fn every_message_gets_a_number_of_its_own() {
        let (a, mut b) = connected_pair("numbers");
        let topic = coin_txs_topic();
        let (first, ..) = publish_until_received(&a, &mut b, &topic, b"one");
        let (second, ..) = publish_until_received(&a, &mut b, &topic, b"two");
        assert_ne!(first, second);
        clean(&[&a, &b]);
    }

    #[test]
    fn a_status_and_a_sync_exchange_cross_between_two_swarms() {
        let (mut a, mut b) = connected_pair("exchange");

        // the status of a reaches b, which answers it by itself
        let status = ToSwarm::Status {
            peer: b.peer.to_bytes(),
            bytes: b"status".to_vec(),
        };
        a.commands.try_send(status).unwrap();
        let got = wire_within(&mut b, WAIT, |message| match message {
            Wire::Status { from, bytes } => Some((from, bytes)),
            _ => None,
        });
        assert_eq!(got, Some((a.peer.to_bytes(), b"status".to_vec())));

        // a request of a is answered by b, with an answer of several MiB
        let ask = ToSwarm::Request {
            id: RequestId(5),
            peer: b.peer.to_bytes(),
            bytes: b"ask".to_vec(),
        };
        a.commands.try_send(ask).unwrap();
        let served = wire_within(&mut b, WAIT, |message| match message {
            Wire::SyncRequest { id, from, bytes } => Some((id, from, bytes)),
            _ => None,
        })
        .unwrap();
        assert_eq!((served.1, served.2), (a.peer.to_bytes(), b"ask".to_vec()));
        let answer = vec![7u8; 3 << 20];
        let reply = ToSwarm::Answer {
            id: served.0,
            bytes: answer.clone(),
        };
        b.commands.try_send(reply).unwrap();
        let got = wire_within(&mut a, WAIT, |message| match message {
            Wire::SyncResponse { id, bytes } => Some((id, bytes)),
            _ => None,
        });
        assert_eq!(got, Some((RequestId(5), answer)));
        clean(&[&a, &b]);
    }

    #[test]
    fn a_request_the_peer_drops_fails_at_the_asker() {
        let (mut a, mut b) = connected_pair("dropped");
        let ask = ToSwarm::Request {
            id: RequestId(6),
            peer: b.peer.to_bytes(),
            bytes: b"ask".to_vec(),
        };
        a.commands.try_send(ask).unwrap();
        let served = wire_within(&mut b, WAIT, |message| match message {
            Wire::SyncRequest { id, .. } => Some(id),
            _ => None,
        })
        .unwrap();
        b.commands.try_send(ToSwarm::Drop { id: served }).unwrap();
        let failed = wire_within(&mut a, WAIT, |message| match message {
            Wire::RequestFailed { id, error } => Some((id, error)),
            _ => None,
        });
        let Some((id, error)) = failed else {
            panic!("the request did not fail");
        };
        assert_eq!(id, RequestId(6));
        assert!(matches!(
            error,
            NetworkError::Transport(_) | NetworkError::Timeout
        ));
        clean(&[&a, &b]);
    }

    #[test]
    fn a_request_to_a_peer_that_cannot_be_reached_fails() {
        let mut a = start_node("lonely", "a", "devnet", vec![]);
        let ask = ToSwarm::Request {
            id: RequestId(7),
            peer: b"not a peer id".to_vec(),
            bytes: b"ask".to_vec(),
        };
        a.commands.try_send(ask).unwrap();
        let failed = wire_within(&mut a, WAIT, |message| match message {
            Wire::RequestFailed { id, error } => Some((id, error)),
            _ => None,
        });
        assert_eq!(
            failed,
            Some((
                RequestId(7),
                NetworkError::Transport(TransportFailure::DialFailure)
            ))
        );
        clean(&[&a]);
    }

    #[test]
    fn a_peer_of_another_network_is_never_reported() {
        let mut a = start_node("other", "a", "devnet", vec![]);
        let mut b = start_node("other", "b", "othernet", vec![a.addr.clone()]);

        assert_eq!(
            connected_within(&mut b, Duration::from_secs(4), 1),
            Vec::<PeerId>::new()
        );
        assert_eq!(
            connected_within(&mut a, Duration::from_secs(1), 1),
            Vec::<PeerId>::new()
        );

        clean(&[&a, &b]);
    }

    #[test]
    fn three_nodes_with_one_bootnode_find_each_other() {
        let mut a = start_node("three", "a", "devnet", vec![]);
        let mut b = start_node("three", "b", "devnet", vec![a.addr.clone()]);
        let mut c = start_node("three", "c", "devnet", vec![a.addr.clone()]);
        let mut seen_by_a = connected_within(&mut a, Duration::from_secs(30), 2);
        let mut seen_by_b = connected_within(&mut b, Duration::from_secs(30), 2);
        let mut seen_by_c = connected_within(&mut c, Duration::from_secs(30), 2);
        seen_by_a.sort();
        seen_by_b.sort();
        seen_by_c.sort();
        let mut want_a = vec![b.peer, c.peer];
        let mut want_b = vec![a.peer, c.peer];
        let mut want_c = vec![a.peer, b.peer];
        want_a.sort();
        want_b.sort();
        want_c.sort();
        assert_eq!(seen_by_a, want_a);
        assert_eq!(seen_by_b, want_b);
        assert_eq!(seen_by_c, want_c);
        clean(&[&a, &b, &c]);
    }

    #[test]
    fn an_address_that_cannot_be_served_is_skipped_when_another_works() {
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let busy = held.local_addr().unwrap().port();
        let free = free_port();
        let dir = std::env::temp_dir().join(format!("pouw-swarm-{}-mixed", std::process::id()));
        let config = TransportConfig {
            network: NetworkName::try_from("devnet".to_owned()).unwrap(),
            listen: vec![
                format!("/ip4/127.0.0.1/tcp/{busy}"),
                format!("/ip4/127.0.0.1/tcp/{free}"),
            ],
            bootnodes: vec![],
            limits: PeerLimits::default(),
            data_dir: dir.clone(),
        };
        assert!(start(&config).is_ok());
        drop(fs::remove_dir_all(&dir));
    }

    #[test]
    fn a_port_in_use_stops_the_start() {
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = held.local_addr().unwrap().port();
        let dir = std::env::temp_dir().join(format!("pouw-swarm-{}-busy", std::process::id()));
        let config = TransportConfig {
            network: NetworkName::try_from("devnet".to_owned()).unwrap(),
            listen: vec![format!("/ip4/127.0.0.1/tcp/{port}")],
            bootnodes: vec![],
            limits: PeerLimits::default(),
            data_dir: dir.clone(),
        };
        assert!(matches!(start(&config), Err(SwarmError::Listen { .. })));
        drop(fs::remove_dir_all(&dir));
    }
}
