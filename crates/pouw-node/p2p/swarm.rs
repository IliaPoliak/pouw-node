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
//! The channel is bounded and the swarm waits for a free slot before it reads the
//! sockets again, as the module doc of [`p2p`](super) describes.
//!
//! Not built yet, each is a part of pouw-node#85 or a later task: gossipsub, the
//! request-response protocols for `Status` and `sync`, the connection limits of
//! [`PeerLimits`](super::PeerLimits) and the ban list.

use std::time::Duration;
use std::{collections::HashSet, io, num::NonZeroUsize, sync::mpsc as std_mpsc, thread};

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder, TransportError, identify,
    identity::Keypair,
    kad,
    multiaddr::Protocol,
    noise,
    swarm::{InvalidProtocol, NetworkBehaviour, SwarmEvent},
    tcp, yamux,
};
use thiserror::Error;
use tokio::{
    runtime,
    sync::mpsc,
    time::{self, MissedTickBehavior},
};
use tracing::{debug, info, warn};

use super::{
    TransportConfig, WIRE_CAPACITY, Wire, WireIn,
    identity::{self, IdentityError},
    protocol,
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
    #[error("the swarm thread ended before it was ready")]
    Gone,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    identify: identify::Behaviour,
    kademlia: kad::Behaviour<kad::store::MemoryStore>,
}

/// What the swarm remembers between events.
#[derive(Debug, Default)]
struct Book {
    /// The peers the node was told about, so a disconnect is reported only for them. Holds
    /// at most the connected peers.
    reported: HashSet<PeerId>,
    /// Whether the one bootstrap query of this run was started.
    bootstrapped: bool,
}

/// Starts the swarm on its own thread and returns the channel it feeds. Returns when the
/// swarm listens on at least one address of `config.listen`: an address the host cannot
/// serve (IPv6 inside a container without it) is logged and skipped, but a node that
/// cannot listen anywhere is an error here and not a silent node without peers.
pub fn start(config: &TransportConfig) -> Result<WireIn, SwarmError> {
    let keypair = identity::load_or_create(&config.data_dir)?;
    let (wire, wire_in) = mpsc::channel(WIRE_CAPACITY);
    let (ready, ready_in) = std_mpsc::sync_channel(1);
    let config = config.clone();
    thread::Builder::new()
        .name("Swarm".to_owned())
        .spawn(move || run(&config, keypair, &wire, &ready))
        .map_err(SwarmError::Thread)?;
    match ready_in.recv() {
        Ok(Ok(())) => Ok(wire_in),
        Ok(Err(error)) => Err(error),
        Err(std_mpsc::RecvError) => Err(SwarmError::Gone),
    }
}

/// The body of the swarm thread. `ready` carries the outcome of the setup, once.
fn run(
    config: &TransportConfig,
    keypair: Keypair,
    wire: &mpsc::Sender<Wire>,
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
        drive(swarm, &bootnodes, &version, wire).await;
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
    let bucket =
        NonZeroUsize::new(config.limits.kademlia_bucket_size).ok_or(SwarmError::BucketSize)?;
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
            Behaviour {
                identify: identify::Behaviour::new(identify_config),
                kademlia,
            }
        });
    Ok(builder
        .with_swarm_config(|config| config.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT))
        .build())
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

/// Handles the swarm events until the transport thread is gone. Dials the bootnodes at
/// once and again every [`REDIAL_INTERVAL`] while no peer is connected.
async fn drive(
    mut swarm: Swarm<Behaviour>,
    bootnodes: &[Multiaddr],
    version: &str,
    wire: &mpsc::Sender<Wire>,
) {
    let mut book = Book::default();
    let mut redial = time::interval(REDIAL_INTERVAL);
    redial.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            event = swarm.select_next_some() => {
                if !on_event(&mut swarm, &mut book, version, event, wire).await {
                    return;
                }
            }
            _ = redial.tick() => dial_bootnodes(&mut swarm, bootnodes),
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
        _ => {}
    }
    true
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
        let wire = start(&config).unwrap();
        let peer = identity::load_or_create(&dir)
            .unwrap()
            .public()
            .to_peer_id();
        Node {
            peer,
            wire,
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
