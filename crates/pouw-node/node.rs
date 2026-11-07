//! The node loop: one thread owns the whole [`NodeState`] and handles one [`Event`]
//! at a time. Every other component runs on its own thread and feeds the loop through
//! one bounded channel per class of producer ([`Feeds`] sends, [`Inbox`] receives).
//! Commands to the transport, gossip verdicts and sync answers among them, go out
//! through [`Network`]; an API caller gets its answer through the oneshot sender in its
//! request ([`reply_to`] counts the ones nobody waits for).
//!
//! ```text
//!  signal thread     -- Control::Shutdown ---------->  +--------------------+
//!  every thread      -- Control::Stopped ----------->  |                    |
//!                                                      |                    |
//!  work worker       -- WorkDone (work) ------------>  |  node loop thread  |
//!                     <-- WorkJob (jobs) ------------  |                    |
//!                                                      |  owns NodeState:   |
//!  transport thread  -- Inbound (p2p) -------------->  |  store, mempool,   |
//!  (libp2p on tokio)  <-- Command over Network -----   |  event log,        |
//!                                                      |  metrics, pending  |
//!  API thread        -- ApiRequest (api) ----------->  |  requests          |
//!  (axum on tokio)    <-- oneshot reply ------------   |                    |
//!  metrics thread    -- ApiRequest::Metrics (api) -->  |  deadline: Tick    |
//!                     <-- oneshot reply ------------   +--------------------+
//! ```
//!
//! Channels, all bounded (capacities are the constants named here):
//!
//! ```text
//!  channel   producers                  capacity          when full
//!  control   signal, every component    CONTROL_CAPACITY  cannot happen: each
//!                                                         sends at most once
//!  work      work worker                WORK_CAPACITY     cannot happen: one job
//!                                                         is in flight
//!  p2p       transport                  P2P_CAPACITY      the sender awaits, so the
//!                                                         transport stops reading
//!  api       API and metrics threads    API_CAPACITY      try_send fails, the caller
//!                                                         answers 503 busy
//!  jobs      loop, to the work worker  JOBS_CAPACITY     cannot happen: the miner
//!                                                         sends no job while
//!                                                         Work::in_flight is set
//!  commands  loop, to the transport     COMMAND_CAPACITY  the command is dropped
//!                                                         and counted in
//!                                                         Metrics::dropped_commands
//!  wire      swarm, to the transport    WIRE_CAPACITY     the swarm awaits, so it
//!            (inside p2p.rs)                              stops reading sockets
//! ```
//!
//! The work worker has one job at a time (see the `miner` module): the loop picks the
//! next one when the worker is free, a received block to verify first, then a proof,
//! then a range of nonces. Received blocks wait in `Work::verify_queue`, which holds
//! `VERIFY_QUEUE_CAP` blocks, and a block that finds it full is dropped and counted in
//! `Metrics::dropped_blocks`.
//!
//! Select priority, highest first: control, work, the tick deadline, p2p, api. The
//! loop thread owns a current-thread tokio runtime and waits on all the receivers at
//! once in [`next_event`], which polls them in that order, so a flood on a lower
//! channel never delays a shutdown, a finished proof or the tick. The tick ranks above
//! p2p and api because it fires once per [`TICK_INTERVAL`] (a late tick is skipped, never
//! queued) and starving it would stall mining and the gauges. The loop never blocks on a
//! full command channel: a transport that is stuck on a full p2p channel could otherwise
//! wait for a loop that waits for the transport.
//!
//! Errors: a handler returns `Result<(), NodeFault>` and [`run`] stops on the first
//! `Err`. A fault is never a verdict on a peer, a transaction or a block: a rule
//! violation is a typed outcome ([`TxOutcome`], [`BlockOutcome`]), a failed store, a
//! gone thread or an exhausted counter is a [`NodeFault`]. [`run`] returns `Ok` only
//! for [`Control::Shutdown`], which the signal thread sends on SIGINT and SIGTERM. Each
//! component thread ends with [`Control::Stopped`]; one that ends with an error is a
//! fault of the node.

use std::{
    future::poll_fn,
    io,
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pouw_api::event::{EventKind, Peer};
use pouw_consensus::{ConsensusParams, InvalidTx, StateError};
use pouw_crypto::Address;
use pouw_provers::ProverError;
use pouw_types::{BlockHeader, BlockId, CumWork, Height, Timestamp};
use thiserror::Error;
use tokio::{
    runtime,
    sync::{mpsc, oneshot},
    task::JoinError,
    time::{Interval, MissedTickBehavior},
};
use tracing::{debug, info, warn};

use crate::{
    api::{self, ApiRequest},
    chain::{self, BlockOutcome, ChainFault, HeaderOutcome, TxOutcome},
    events::{self, EventLog, SeqExhausted},
    mempool::{self, Mempool},
    metrics::{self, Metrics},
    miner::{self, InFlight, Work, WorkDone},
    p2p::{
        self, Acceptance, Command, Gossip, Inbound, MessageId, Misbehavior, Network, NetworkError,
        PeerIx, PeerIxExhausted, RequestId, ServeId, Status, SyncRequest, TransportGone,
        protocol::{PROTOCOL_VERSION, Services},
    },
    precheck::{CheckedAnnounce, CheckedBlock, CheckedTx, Fetched},
    store::{self, Store, StoreError},
    sync::{self, Pending, SyncError, SyncOutcome, SyncedBlocks},
};

/// Time between two ticks.
pub const TICK_INTERVAL: Duration = Duration::from_secs(1);

/// Ticks between two `mempool_snapshot` events.
pub const SNAPSHOT_EVERY_TICKS: u64 = 10;

/// Every component thread, which sends one [`Control::Stopped`] when it ends.
pub const COMPONENTS: [Component; 5] = [
    Component::P2p,
    Component::Api,
    Component::Metrics,
    Component::Prover,
    Component::Signals,
];

/// One `Stopped` per component and the one `Shutdown` of the signal thread, so a send
/// on this channel never waits.
pub const CONTROL_CAPACITY: usize = COMPONENTS.len() + 1;

/// One job is in flight at a time, so at most one result waits.
pub const WORK_CAPACITY: usize = 1;

/// One job is in flight at a time, so at most one job waits.
pub const JOBS_CAPACITY: usize = 1;

/// Decoded gossip waits in this channel, each up to one block (`MAX_BLOCK_BYTES`, 8 MiB):
/// 16 of them bound the queued payload at 128 MiB.
pub const P2P_CAPACITY: usize = 16;

/// A queued call is a few words, except a `SubmitTx`, which owns one boxed transaction
/// of at most 1 MiB (`MAX_WITNESS_BYTES`, `MAX_RELAY_CIRCUIT_BYTES`): 64 of them bound
/// the queue at about 64 MiB, and beyond that a 503 serves a caller better than a wait.
pub const API_CAPACITY: usize = 64;

/// Commands to the transport: a few per inbound message, so 256 holds the answers to a
/// full p2p channel and the loop never waits for a slow transport.
pub const COMMAND_CAPACITY: usize = 256;

/// The measured size of [`Event`] must stay under this, so a queue slot is one cache
/// line and large payloads are boxed.
pub const MAX_EVENT_BYTES: usize = 64;

const _: () = assert!(size_of::<Event>() <= MAX_EVENT_BYTES);

/// The sending ends of the loop's channels. Cloned into the components, each of which
/// takes the ends it needs.
#[derive(Debug, Clone)]
pub struct Feeds {
    pub control: mpsc::Sender<Control>,
    pub work: mpsc::Sender<WorkDone>,
    pub p2p: mpsc::Sender<Inbound>,
    pub api: mpsc::Sender<ApiRequest>,
}

/// The receiving ends of the loop's channels, owned by the loop thread.
#[derive(Debug)]
pub struct Inbox {
    pub control: mpsc::Receiver<Control>,
    pub work: mpsc::Receiver<WorkDone>,
    pub p2p: mpsc::Receiver<Inbound>,
    pub api: mpsc::Receiver<ApiRequest>,
}

/// The channels of the loop with the capacities above.
pub fn channels() -> (Feeds, Inbox) {
    let (control_tx, control_rx) = mpsc::channel(CONTROL_CAPACITY);
    let (work_tx, work_rx) = mpsc::channel(WORK_CAPACITY);
    let (p2p_tx, p2p_rx) = mpsc::channel(P2P_CAPACITY);
    let (api_tx, api_rx) = mpsc::channel(API_CAPACITY);
    let feeds = Feeds {
        control: control_tx,
        work: work_tx,
        p2p: p2p_tx,
        api: api_tx,
    };
    let inbox = Inbox {
        control: control_rx,
        work: work_rx,
        p2p: p2p_rx,
        api: api_rx,
    };
    (feeds, inbox)
}

/// The source of the current time. A test sets its own.
pub type Clock = fn() -> Timestamp;

/// The wall clock in seconds since the Unix epoch. The loop reads it once per block it
/// checks and hands it to consensus, which reads no clock itself.
pub fn system_clock() -> Timestamp {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp(elapsed.as_secs())
}

/// Everything the loop owns.
#[derive(Debug)]
pub struct NodeState {
    /// The consensus parameters of the chain.
    pub params: ConsensusParams,
    /// `min_chain_work` of the chain spec: initial block download (pouw-node#90) does not
    /// take a chain below this cumulative work as the best one.
    pub min_chain_work: CumWork,
    /// `assume_valid` of the chain spec: initial block download (pouw-node#90) may skip
    /// the verify-work stage (`miner::verify_work`) of the ancestors of this block. The
    /// stage is the one job kind that may be left out, so the verify queue sees none of
    /// them.
    pub assume_valid: Option<BlockId>,
    /// The services this node offers peers in its [`Status`].
    pub services: Services,
    /// Receiver of the rewards; the node mines only when set.
    pub miner: Option<Address>,
    pub store: Store,
    pub mempool: Mempool,
    pub events: EventLog,
    pub metrics: Metrics,
    pub network: Network,
    /// Requests to peers that wait for their [`Inbound::Response`].
    pub pending: Pending,
    /// The id of the next request to a peer.
    pub next_request: RequestId,
    /// The work slot, the verify queue and the block being mined.
    pub work: Work,
    /// The current time.
    pub clock: Clock,
    /// Ticks handled so far.
    pub ticks: u64,
}

/// The threads around the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    P2p,
    Api,
    Metrics,
    Prover,
    /// Waits for SIGINT and SIGTERM and sends [`Control::Shutdown`].
    Signals,
}

/// Why a component thread ended with an error.
#[derive(Debug, Error)]
pub enum ComponentFault {
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[from] io::Error),
    #[error("a task of the component failed: {0}")]
    Task(#[from] JoinError),
    /// The loop dropped its end of a channel. This is how a component learns that the
    /// node is shutting down.
    #[error("the node loop is gone")]
    NodeGone,
    /// The swarm glue handed over a peer id that no libp2p peer can have.
    #[error("the swarm handed over a bad peer id: {0}")]
    BadPeerId(#[from] p2p::PeerIdTooLong),
    #[error(transparent)]
    PeerIndex(#[from] PeerIxExhausted),
}

/// Why [`run`] stopped without a [`Control::Shutdown`]. The loop stops on the first
/// fault, and only `main` decides what the process does about it.
#[derive(Debug, Error)]
pub enum NodeFault {
    #[error("cannot start the loop runtime: {0}")]
    Runtime(#[source] io::Error),
    #[error("the store failed: {0}")]
    Store(#[from] StoreError),
    #[error(transparent)]
    TransportGone(#[from] TransportGone),
    #[error("the work worker is gone")]
    ProverGone,
    #[error("the state could not be read: {0}")]
    State(#[from] StateError),
    #[error("prover failure: {0}")]
    Prover(ProverError),
    #[error("the event log: {0}")]
    EventSeq(#[from] SeqExhausted),
    #[error("the request ids are exhausted")]
    RequestIds,
    #[error("the {component:?} component failed: {source}")]
    Component {
        component: Component,
        source: ComponentFault,
    },
    /// Every sender of the control channel is gone, but nobody sent
    /// [`Control::Shutdown`].
    #[error("the control channel closed without a shutdown")]
    InboxClosed,
}

impl From<ChainFault> for NodeFault {
    fn from(fault: ChainFault) -> Self {
        match fault {
            ChainFault::Store(store) => Self::Store(store),
            ChainFault::Events(events) => Self::EventSeq(events),
            ChainFault::State(state) => Self::State(state),
            ChainFault::Prover(prover) => Self::Prover(prover),
        }
    }
}

impl From<SyncError> for NodeFault {
    fn from(error: SyncError) -> Self {
        match error {
            SyncError::Store(store) => Self::Store(store),
            SyncError::TransportGone(gone) => Self::TransportGone(gone),
            SyncError::IdsExhausted => Self::RequestIds,
        }
    }
}

/// What arrives on the control channel.
#[derive(Debug)]
pub enum Control {
    /// A component thread ended; its last act. Ending without an error leaves the node
    /// running, as the API and metrics threads do while their servers are stubs.
    Stopped(Component, Result<(), ComponentFault>),
    Shutdown,
}

/// What the loop handles. The size is bounded by [`MAX_EVENT_BYTES`]: peers are
/// [`PeerIx`] and big payloads are boxed.
#[derive(Debug)]
pub enum Event {
    Control(Control),
    Work(WorkDone),
    Tick,
    Net(Inbound),
    Api(ApiRequest),
}

/// Waits for the next event: control, then work, then the tick, then p2p, then api.
/// A closed work, p2p or api channel is skipped (its owner reports itself through
/// [`Control::Stopped`]), a closed control channel is [`NodeFault::InboxClosed`].
pub async fn next_event(inbox: &mut Inbox, tick: &mut Interval) -> Result<Event, NodeFault> {
    poll_fn(|cx| {
        match inbox.control.poll_recv(cx) {
            Poll::Ready(Some(control)) => return Poll::Ready(Ok(Event::Control(control))),
            Poll::Ready(None) => return Poll::Ready(Err(NodeFault::InboxClosed)),
            Poll::Pending => {}
        }
        if let Poll::Ready(Some(done)) = inbox.work.poll_recv(cx) {
            return Poll::Ready(Ok(Event::Work(done)));
        }
        if tick.poll_tick(cx).is_ready() {
            return Poll::Ready(Ok(Event::Tick));
        }
        if let Poll::Ready(Some(inbound)) = inbox.p2p.poll_recv(cx) {
            return Poll::Ready(Ok(Event::Net(inbound)));
        }
        if let Poll::Ready(Some(request)) = inbox.api.poll_recv(cx) {
            return Poll::Ready(Ok(Event::Api(request)));
        }
        Poll::Pending
    })
    .await
}

/// Handles events until [`Control::Shutdown`], which is the only way to return `Ok`.
/// Any fault, including a closed control channel, stops the loop and is returned.
pub fn run(state: &mut NodeState, inbox: &mut Inbox) -> Result<(), NodeFault> {
    let runtime = runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .map_err(NodeFault::Runtime)?;
    runtime.block_on(async {
        let mut tick = tokio::time::interval(TICK_INTERVAL);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            let event = next_event(inbox, &mut tick).await?;
            if handle(state, event)? == Flow::Stop {
                return Ok(());
            }
        }
    })
}

/// Whether the loop goes on after an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Stop,
}

/// Handles one event. [`Flow::Stop`] is the answer to [`Control::Shutdown`] only.
pub fn handle(state: &mut NodeState, event: Event) -> Result<Flow, NodeFault> {
    match event {
        Event::Control(Control::Shutdown) => return Ok(Flow::Stop),
        Event::Control(Control::Stopped(component, Ok(()))) => {
            warn!(
                ?component,
                "a component finished and the node keeps running"
            );
        }
        Event::Control(Control::Stopped(component, Err(source))) => {
            return Err(NodeFault::Component { component, source });
        }
        Event::Work(done) => on_work(state, done)?,
        Event::Tick => on_tick(state)?,
        Event::Net(Inbound::Gossip { id, from, message }) => {
            on_gossip(state, id, from, message)?;
        }
        Event::Net(Inbound::Status { from, status }) => on_status(state, from, &status)?,
        Event::Net(Inbound::Request { serve, request, .. }) => {
            on_request(state, serve, &request)?;
        }
        Event::Net(Inbound::Response { id, result }) => on_response(state, id, result)?,
        Event::Net(Inbound::PeerConnected { peer, peer_id }) => {
            on_peer_connected(state, peer, &peer_id)?;
        }
        Event::Net(Inbound::PeerDisconnected { peer, peer_id }) => {
            on_peer_disconnected(state, peer, &peer_id)?;
        }
        Event::Api(ApiRequest::Tip { reply }) => {
            reply_to(reply, api::tip(&state.store), &mut state.metrics);
        }
        Event::Api(ApiRequest::Header { id, reply }) => {
            reply_to(reply, api::header(&state.store, &id), &mut state.metrics);
        }
        Event::Api(ApiRequest::Block { id, reply }) => {
            reply_to(reply, api::block(&state.store, &id), &mut state.metrics);
        }
        Event::Api(ApiRequest::Account { address, reply }) => {
            reply_to(
                reply,
                api::account(&state.store, &address),
                &mut state.metrics,
            );
        }
        Event::Api(ApiRequest::SubmitTx { checked, reply }) => {
            on_submit_tx(state, *checked, reply)?;
        }
        Event::Api(ApiRequest::TxLocation { id, reply }) => {
            reply_to(
                reply,
                api::tx_location(&state.store, &id),
                &mut state.metrics,
            );
        }
        Event::Api(ApiRequest::Events {
            after,
            limit,
            reply,
        }) => {
            reply_to(
                reply,
                api::events(&state.events, after, limit),
                &mut state.metrics,
            );
        }
        Event::Api(ApiRequest::Mempool { reply }) => {
            reply_to(reply, mempool::view(&state.mempool), &mut state.metrics);
        }
        Event::Api(ApiRequest::Metrics { reply }) => {
            let text = metrics::render(&state.metrics);
            reply_to(reply, text, &mut state.metrics);
        }
    }
    Ok(Flow::Continue)
}

/// Answers a caller through its oneshot. A caller that stopped waiting is counted in
/// [`Metrics::dropped_replies`].
pub fn reply_to<T>(to: oneshot::Sender<T>, value: T, metrics: &mut Metrics) {
    if to.send(value).is_err() {
        metrics.dropped_replies = metrics.dropped_replies.saturating_add(1);
    }
}

/// Sends `control` from a component thread to the loop. The channel has room for every
/// message a component can send ([`CONTROL_CAPACITY`]), so this does not wait.
pub fn to_control(control: &mpsc::Sender<Control>, message: Control) -> Result<(), ComponentFault> {
    control
        .blocking_send(message)
        .map_err(|mpsc::error::SendError(_)| ComponentFault::NodeGone)
}

/// The last act of a component thread: tells the loop how the thread ended. When the
/// loop is gone already nobody is left to tell.
pub fn stopped(
    control: &mpsc::Sender<Control>,
    component: Component,
    result: Result<(), ComponentFault>,
) {
    if to_control(control, Control::Stopped(component, result)).is_err() {
        info!(?component, "component ended after the node loop");
    }
}

/// Handles a result of the work worker. A block whose work claim is valid connects like
/// a received block, one whose claim is not is reported against the peer it came from.
fn on_work(state: &mut NodeState, done: WorkDone) -> Result<(), NodeFault> {
    match done {
        WorkDone::Nonce(done) => miner::on_nonce(state, done),
        WorkDone::Proof(done) => miner::on_proof(state, done),
        WorkDone::Verified(verified) => {
            let miner::VerifiedWork { block, verdict } = *verified;
            let slot = state.work.in_flight.take();
            let Some(InFlight::Verify { peer, .. }) = slot else {
                warn!("a verified block arrived with no verification in flight");
                return miner::dispatch(state);
            };
            match verdict {
                Ok(()) => connect_verified(state, peer, &block)?,
                Err(invalid) => {
                    warn!(%invalid, ?peer, "a block with a bad work claim");
                    report(state, peer, Misbehavior::InvalidBlock)?;
                }
            }
            miner::dispatch(state)
        }
    }
}

/// Handles a gossip message and sends the transport its verdict as
/// [`Command::Validate`].
fn on_gossip(
    state: &mut NodeState,
    id: MessageId,
    from: PeerIx,
    message: Gossip,
) -> Result<(), NodeFault> {
    let topic = message.topic();
    let acceptance = match message {
        Gossip::Tx(tx) => {
            let outcome = chain::receive_tx(
                &state.store,
                &state.params,
                &mut state.mempool,
                &mut state.events,
                *tx,
            )?;
            chain::tx_acceptance(&outcome)
        }
        Gossip::Announce(announce) => on_announce(state, from, &announce)?,
    };
    let verdict = Command::Validate {
        id,
        from,
        topic,
        acceptance,
    };
    p2p::send(&state.network, verdict, &mut state.metrics)?;
    Ok(())
}

/// Handles the header a peer announces, whose chain id and work claim the precheck
/// verified, through [`chain::receive_header`]. The verdict for the transport:
/// - the id is indexed already: `Ignore`, the block is known or being fetched
/// - the header passes the rules against its stored parent: it is stored, the block is
///   requested from the announcer with `GetBlocks`, and the verdict is `Accept` so the
///   announcement is relayed
/// - the parent is not stored: `Ignore`, and header sync starts with a `GetHeaders` of
///   our locator to the announcer, which answers with the headers that connect
/// - the header breaks a rule (height, target, timestamp, version): `Reject`, the
///   announcer is penalized and the header is not stored
fn on_announce(
    state: &mut NodeState,
    from: PeerIx,
    announce: &CheckedAnnounce,
) -> Result<Acceptance, NodeFault> {
    let CheckedAnnounce { header, id } = announce;
    match chain::receive_header(&mut state.store, &state.params, (state.clock)(), id, header)? {
        HeaderOutcome::Known => Ok(Acceptance::Ignore),
        HeaderOutcome::Stored(_) => {
            sync::ask_block(
                &state.network,
                &mut state.pending,
                &mut state.next_request,
                &mut state.metrics,
                from,
                *id,
            )?;
            Ok(Acceptance::Accept)
        }
        HeaderOutcome::UnknownParent => {
            sync::ask_headers(
                &state.network,
                &mut state.pending,
                &mut state.next_request,
                &state.store,
                &mut state.metrics,
                from,
            )?;
            Ok(Acceptance::Ignore)
        }
        HeaderOutcome::Invalid(invalid) => {
            debug!(%invalid, %id, peer = ?from, "an announced header breaks a rule");
            Ok(Acceptance::Reject)
        }
    }
}

/// Our [`Status`], read from the store.
pub(crate) fn our_status(state: &NodeState) -> Result<Status, StoreError> {
    let reader = store::read(&state.store)?;
    let tip = store::tip(&reader)?.ok_or_else(|| StoreError::Corrupt("no tip".into()))?;
    let genesis = store::canonical_id(&reader, Height(0))?
        .ok_or_else(|| StoreError::Corrupt("no genesis".into()))?;
    Ok(Status {
        protocol_version: PROTOCOL_VERSION,
        chain_id: state.params.chain_id,
        genesis,
        tip: tip.id,
        height: tip.height,
        cumulative_work: tip.cumulative_work,
        services: state.services,
        agent: format!("pouw-node/{}", env!("CARGO_PKG_VERSION")),
    })
}

/// Handles the [`Status`] of a peer. A different protocol version, chain id or genesis
/// is answered with [`Command::Disconnect`] and no penalty. A peer with more
/// cumulative work than ours is asked for headers with our locator.
fn on_status(state: &mut NodeState, from: PeerIx, status: &Status) -> Result<(), NodeFault> {
    let ours = our_status(state)?;
    if let Err(reason) = status.compatible(&ours) {
        info!(peer = ?from, %reason, "disconnecting a peer on another chain");
        let command = Command::Disconnect { peer: from, reason };
        p2p::send(&state.network, command, &mut state.metrics)?;
        return Ok(());
    }
    if status.cumulative_work > ours.cumulative_work {
        sync::ask_headers(
            &state.network,
            &mut state.pending,
            &mut state.next_request,
            &state.store,
            &mut state.metrics,
            from,
        )?;
    }
    Ok(())
}

/// Answers a sync request of a peer from the store with [`Command::Answer`]. The
/// answer is a command, not a oneshot, so the transport needs no task per request: it
/// keeps the response channel of the request under `serve`.
fn on_request(
    state: &mut NodeState,
    serve: ServeId,
    request: &SyncRequest,
) -> Result<(), NodeFault> {
    let response = sync::answer(&state.store, request)?;
    let answer = Command::Answer {
        id: serve,
        response,
    };
    p2p::send(&state.network, answer, &mut state.metrics)?;
    Ok(())
}

fn on_response(
    state: &mut NodeState,
    id: RequestId,
    result: Result<Fetched, NetworkError>,
) -> Result<(), NodeFault> {
    match sync::on_response(&mut state.pending, id, result) {
        SyncOutcome::Blocks(synced) => connect_synced(state, synced),
        SyncOutcome::Misbehaved(peer, why) => report(state, peer, why),
        SyncOutcome::Headers { peer, headers } => on_headers(state, peer, &headers),
        SyncOutcome::Unreachable { peer, error } => {
            warn!(%error, ?peer, "sync request failed");
            Ok(())
        }
        SyncOutcome::Unsolicited => Ok(()),
        SyncOutcome::TransportStopped => Err(NodeFault::TransportGone(TransportGone)),
    }
}

/// Headers-first initial block download, pouw-node#90. Called with the headers `peer`
/// sent after our `GetHeaders`, at most [`MAX_HEADERS_PER_RESPONSE`](p2p::limits::MAX_HEADERS_PER_RESPONSE) of them, each
/// already prechecked for the chain id and its work claim. A peer is asked for headers
/// by [`on_status`] when its cumulative work is above ours, and by [`on_announce`] when
/// an announced parent is unknown.
///
/// To build:
/// 1. Each header after the first has the id of the one before as parent; a break is
///    [`Misbehavior::InvalidBlock`] for `peer` (see [`report`]).
/// 2. Pass each header in order to [`chain::receive_header`]. `Known` is skipped,
///    `Stored` is kept for step 4, `Invalid` is [`Misbehavior::InvalidBlock`] and ends the
///    answer. `UnknownParent` on the first header means the peer ignored our locator, and
///    is [`Misbehavior::InvalidBlock`] too.
/// 3. A full answer of [`MAX_HEADERS_PER_RESPONSE`](p2p::limits::MAX_HEADERS_PER_RESPONSE) headers means more follow: ask again
///    with `sync::ask_headers`, whose locator now starts at the stored headers.
/// 4. Fetch bodies only once the cumulative work of the last stored header
///    ([`IndexEntry::work`](store::schema::IndexEntry::work)) reaches `state.min_chain_work`, so a long chain of
///    little work costs no downloads. Then ask for the bodies whose block is not stored,
///    in height order, with `sync::request` and a [`SyncRequest::GetBlocks`] of at most
///    [`MAX_BLOCKS_PER_REQUEST`](p2p::limits::MAX_BLOCKS_PER_REQUEST) ids. Keep one window in flight per peer and never ask
///    two peers for the same id; the window bookkeeping is a new plain field of
///    [`NodeState`].
/// 5. The bodies come back as a `Blocks` answer to [`on_response`] and connect through
///    [`connect_synced`], the verify queue and `chain::receive_block`. When a window is answered, ask the
///    next one.
/// 6. `state.assume_valid`: for its ancestors the verify-work stage
///    (`miner::verify_work`, which holds the Groth16 payload verify) may
///    be skipped, as Bitcoin's `assumevalid` skips script checks. Header, target,
///    timestamp and linking rules (step 2) and the other body rules still run for
///    every block.
///
/// Limits: one `GetHeaders` and one window per peer at a time, and a peer that does not
/// answer in time is [`Misbehavior::Unresponsive`].
///
/// Test: a node that starts empty with one peer that holds a chain of 5000 blocks
/// reaches the tip of the peer, with the stored headers and bodies equal to the peer's.
/// A second test uses a peer on a fork with more work and expects the chain to switch.
fn on_headers(
    _state: &mut NodeState,
    peer: PeerIx,
    headers: &[BlockHeader],
) -> Result<(), NodeFault> {
    todo!(
        "pouw-node#90: initial block download from {peer:?} with {} headers",
        headers.len()
    )
}

/// Queues the received bodies for their work check, in order, so a block is checked and
/// connected before the next one, which extends it.
fn connect_synced(state: &mut NodeState, synced: SyncedBlocks) -> Result<(), NodeFault> {
    for block in synced.blocks {
        miner::enqueue_verify(state, synced.peer, block)?;
    }
    Ok(())
}

fn connect_verified(
    state: &mut NodeState,
    peer: PeerIx,
    block: &CheckedBlock,
) -> Result<(), NodeFault> {
    let outcome = chain::receive_block(
        &mut state.store,
        &mut state.mempool,
        &mut state.events,
        &mut state.metrics,
        &state.params,
        (state.clock)(),
        block,
    )?;
    match outcome {
        BlockOutcome::Invalid(invalid) => {
            warn!(%invalid, ?peer, "a synced block is invalid");
            report(state, peer, Misbehavior::InvalidBlock)
        }
        BlockOutcome::ParentFailed(id) => {
            warn!(%id, ?peer, "a synced block extends a failed block");
            report(state, peer, Misbehavior::InvalidBlock)
        }
        _ => {
            debug!(?outcome, "a block with verified work");
            Ok(())
        }
    }
}

fn report(state: &mut NodeState, peer: PeerIx, why: Misbehavior) -> Result<(), NodeFault> {
    p2p::send(
        &state.network,
        Command::Report(peer, why),
        &mut state.metrics,
    )?;
    Ok(())
}

fn on_peer_connected(state: &mut NodeState, peer: PeerIx, peer_id: &str) -> Result<(), NodeFault> {
    state.metrics.peers = state.metrics.peers.saturating_add(1);
    events::emit(
        &mut state.events,
        EventKind::PeerConnected(peer_view(peer_id)),
    )?;
    let status = Box::new(our_status(state)?);
    let command = Command::Status { peer, status };
    p2p::send(&state.network, command, &mut state.metrics)?;
    Ok(())
}

fn on_peer_disconnected(
    state: &mut NodeState,
    peer: PeerIx,
    peer_id: &str,
) -> Result<(), NodeFault> {
    state.metrics.peers = state.metrics.peers.saturating_sub(1);
    events::emit(
        &mut state.events,
        EventKind::PeerDisconnected(peer_view(peer_id)),
    )?;
    sync::on_peer_disconnected(&mut state.pending, peer);
    Ok(())
}

fn on_submit_tx(
    state: &mut NodeState,
    checked: Result<CheckedTx, InvalidTx>,
    reply: oneshot::Sender<TxOutcome>,
) -> Result<(), NodeFault> {
    let outcome = match checked {
        Ok(checked) => {
            let broadcast = Command::Broadcast(Gossip::Tx(Box::new(checked.clone())));
            let outcome = chain::receive_tx(
                &state.store,
                &state.params,
                &mut state.mempool,
                &mut state.events,
                checked,
            )?;
            if matches!(outcome, TxOutcome::Pooled(_)) {
                p2p::send(&state.network, broadcast, &mut state.metrics)?;
            }
            outcome
        }
        Err(invalid) => chain::reject_tx(&mut state.events, invalid)?,
    };
    reply_to(reply, outcome, &mut state.metrics);
    Ok(())
}

pub(crate) fn on_tick(state: &mut NodeState) -> Result<(), NodeFault> {
    refresh_gauges(&mut state.metrics, &state.store, &state.mempool)?;
    state.ticks = state.ticks.saturating_add(1);
    if state.ticks.checked_rem(SNAPSHOT_EVERY_TICKS) == Some(0) {
        let snapshot = mempool::snapshot(&state.mempool);
        events::emit(&mut state.events, EventKind::MempoolSnapshot(snapshot))?;
    }
    miner::dispatch(state)
}

fn refresh_gauges(
    metrics: &mut Metrics,
    store: &Store,
    mempool: &Mempool,
) -> Result<(), StoreError> {
    let tip = store::tip(&store::read(store)?)?;
    metrics.height = tip.map_or(Height(0), |tip| tip.height).0;
    metrics.mempool_size = mempool::count(mempool.txs.len());
    Ok(())
}

fn peer_view(peer_id: &str) -> Peer {
    Peer {
        peer_id: peer_id.to_owned(),
    }
}

#[cfg(test)]
mod tests;
