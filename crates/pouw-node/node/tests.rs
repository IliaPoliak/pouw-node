use std::{cell::Cell, collections::VecDeque, time::Duration};

use pouw_api::{event::EventKind, view::HeaderView};
use pouw_consensus::{Anchor, Change, InvalidTx, Scratch, StateDiff, next_target};
use pouw_crypto::{Address, Hash32, SigningKey};
use pouw_provers::{MockProver, Prover, Statement};
use pouw_types::{
    Amount, Block, BlockHeader, BlockId, ChainId, CircuitEntry, CircuitId, ConsensusParams,
    ConstraintCount, CumWork, Height, Nonce, ProofSystem, SignedTx, SystemId, Target, Timestamp,
    TxBody, TxId, TxKind, U32, U64, UsageCounter, block_id, block_work, eta_chain, mask, sign_body,
    txid,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::Interval,
};

use crate::{
    api::{self, ApiRequest},
    chain::{self, TxOutcome},
    events::{self, EventLog},
    mempool::{self, MempoolLimits},
    metrics::Metrics,
    miner::{self, ProofDone, WorkDone, WorkJob},
    node::{
        self, Component, ComponentFault, Control, Event, Feeds, Flow, Inbox, NodeFault, NodeState,
    },
    p2p::{
        Acceptance, Command, DisconnectReason, GetBlocks, GetHeaders, Gossip, Inbound, MessageId,
        Misbehavior, Outbound, PeerIx, RequestId, ServeId, Status, SyncRequest, SyncResponse,
        Topic,
        protocol::{PROTOCOL_VERSION, Services},
    },
    precheck::{self, CheckedAnnounce, CheckedBlock, CheckedTx, Fetched},
    store,
    sync::PendingRequest,
};

const CHAIN: ChainId = ChainId(1);

/// Parameters with a target a test mines in a few hundred ids.
fn test_params() -> ConsensusParams {
    let mut easiest = [0xff; 32];
    easiest[0] = 0x00;
    ConsensusParams {
        chain_id: CHAIN,
        initial_subsidy: Amount(50),
        halving_interval: 210_000,
        target_block_secs: 10,
        half_life_secs: 600,
        initial_target: Target(easiest),
        pow_limit: Target(easiest),
        max_future_secs: 300,
        fee_per_public_input: Amount(1),
        fee_per_witness_kib: Amount(1),
    }
}

struct Harness {
    state: NodeState,
    outbound: Outbound,
    feeds: Feeds,
    inbox: Inbox,
    jobs: mpsc::Receiver<WorkJob>,
    prover: Prover,
    next_message: u64,
}

thread_local! {
    static CLOCK: Cell<u64> = const { Cell::new(GENESIS_TIME + 100_000) };
}

fn test_clock() -> Timestamp {
    Timestamp(CLOCK.with(Cell::get))
}

fn set_clock(seconds: u64) {
    CLOCK.with(|clock| clock.set(seconds));
}

fn harness() -> Harness {
    let (network, outbound) = mpsc::channel(node::COMMAND_CAPACITY);
    let (prover_jobs, jobs) = mpsc::channel(node::JOBS_CAPACITY);
    let (feeds, inbox) = node::channels();
    let state = NodeState {
        params: test_params(),
        min_chain_work: CumWork::ZERO,
        assume_valid: None,
        services: Services::ARCHIVE,
        miner: None,
        store: store::memory(),
        mempool: mempool::new(MempoolLimits {
            max_bytes: 1 << 20,
            sender_slots: 16,
        }),
        events: EventLog {
            node_id: "node-a".parse().unwrap(),
            retention: 100,
            events: VecDeque::new(),
            last_seq: 0,
        },
        metrics: Metrics::default(),
        network,
        pending: Vec::new(),
        next_request: RequestId(0),
        work: miner::new_work(prover_jobs),
        clock: test_clock,
        ticks: 0,
    };
    Harness {
        state,
        outbound,
        feeds,
        inbox,
        jobs,
        prover: Prover::from(MockProver::default()),
        next_message: 0,
    }
}

/// Handles events in the order of the loop (control, work, p2p, api), one thread, and
/// runs the work worker whenever a job waits, until `done` is true or nothing is left.
/// A shutdown or a fault ends it.
fn pump_until(h: &mut Harness, mut done: impl FnMut(&Harness) -> bool) -> Result<(), NodeFault> {
    loop {
        if done(h) {
            return Ok(());
        }
        let event = if let Ok(control) = h.inbox.control.try_recv() {
            Event::Control(control)
        } else if let Ok(work) = h.inbox.work.try_recv() {
            Event::Work(work)
        } else if let Ok(job) = h.jobs.try_recv() {
            let finished = miner::run_job(&h.prover, &h.state.params, job);
            h.feeds.work.try_send(finished).unwrap();
            continue;
        } else if let Ok(inbound) = h.inbox.p2p.try_recv() {
            Event::Net(inbound)
        } else if let Ok(request) = h.inbox.api.try_recv() {
            Event::Api(request)
        } else {
            return Ok(());
        };
        if node::handle(&mut h.state, event)? == Flow::Stop {
            return Ok(());
        }
    }
}

/// Handles everything queued and every job it causes, until the node is idle.
fn run_loop(h: &mut Harness) -> Result<(), NodeFault> {
    pump_until(h, |_| false)
}

fn run(h: &mut Harness) {
    run_loop(h).unwrap();
}

fn peer() -> PeerIx {
    PeerIx(7)
}

fn to_node(h: &Harness, inbound: Inbound) {
    h.feeds.p2p.try_send(inbound).unwrap();
}

fn to_api(h: &Harness, request: ApiRequest) {
    h.feeds.api.try_send(request).unwrap();
}

fn signed(nonce: u64, kind: TxKind) -> SignedTx {
    let key = SigningKey::from_seed([1; 32]);
    sign_body(
        &TxBody {
            chain_id: CHAIN,
            sender: key.address(),
            nonce: Nonce(nonce),
            fee: Amount(1),
            kind,
        },
        &key,
    )
}

fn transfer(chain_id: ChainId, nonce: u64) -> SignedTx {
    transfer_from(1, chain_id, nonce)
}

fn transfer_from(seed: u8, chain_id: ChainId, nonce: u64) -> SignedTx {
    let key = SigningKey::from_seed([seed; 32]);
    sign_body(
        &TxBody {
            chain_id,
            sender: key.address(),
            nonce: Nonce(nonce),
            fee: Amount(1),
            kind: TxKind::Transfer {
                to: Address([2; 32]),
                amount: Amount(3),
            },
        },
        &key,
    )
}

const GENESIS_TIME: u64 = 1_000;

fn genesis_block() -> Block {
    raw_block(
        0,
        BlockId::ZERO,
        GENESIS_TIME,
        test_params().initial_target,
        vec![],
    )
}

/// A sealed block whose header meets its own target.
fn raw_block(
    height: u64,
    parent: BlockId,
    timestamp: u64,
    target: Target,
    txs: Vec<SignedTx>,
) -> Block {
    let mut block = Block {
        header: BlockHeader {
            version: U32::new(1),
            chain_id: U32::new(CHAIN.0),
            system_id: U64::new(0),
            height: U64::new(height),
            parent,
            timestamp: U64::new(timestamp),
            miner: Address([9; 32]),
            tx_root: Hash32::ZERO,
            target,
            nonce: U64::new(0),
        },
        txs,
        proof_txs: vec![],
    };
    block.header.tx_root = block.compute_tx_root();
    remine(block)
}

/// Searches a nonce until the header meets its target.
fn remine(mut block: Block) -> Block {
    while block_id(&block.header).0.0 > block.header.target.0 {
        block.header.nonce = U64::new(block.header.nonce.get().wrapping_add(1));
    }
    block
}

/// The valid child of `parent`: one second later, with the target of the rule.
fn block(parent: &Block, txs: Vec<SignedTx>) -> Block {
    let params = test_params();
    let anchor = Anchor::first_block(&params, &genesis_block().header);
    let target = next_target(&params, SystemId(0), &anchor, &parent.header).unwrap();
    raw_block(
        parent.header.height.get().saturating_add(1),
        block_id(&parent.header),
        parent.header.timestamp.get().saturating_add(1),
        target,
        txs,
    )
}

fn txids(block: &Block) -> Vec<TxId> {
    let mut txids = Vec::new();
    block.txids_into(&mut txids);
    txids
}

fn checked(block: Block) -> CheckedBlock {
    CheckedBlock {
        bytes: borsh::to_vec(&block).unwrap(),
        txids: txids(&block),
        block,
    }
}

fn checked_tx(tx: SignedTx) -> CheckedTx {
    CheckedTx {
        txid: txid(&tx),
        tx,
    }
}

/// A transaction as the API thread hands it to the loop, after its precheck.
fn submitted(tx: SignedTx) -> Box<Result<CheckedTx, InvalidTx>> {
    Box::new(precheck::check_tx(tx, CHAIN, &mut Scratch::default()))
}

fn pool(h: &mut Harness, tx: SignedTx) {
    crate::mempool::insert(&mut h.state.mempool, txid(&tx), tx).unwrap();
}

/// Stores `block` as received and returns its id.
fn put(store: &mut store::Store, block: &Block) -> BlockId {
    let id = block_id(&block.header);
    store::put_header(store, &id, &block.header).unwrap();
    store::put_body(store, &id, &borsh::to_vec(block).unwrap()).unwrap();
    id
}

/// A balance for every test key (the seeds 0 to 255), so that blocks which spend pass the
/// state transition.
fn funded() -> StateDiff {
    let mut diff = StateDiff::default();
    for seed in 0..=u8::MAX {
        let address = SigningKey::from_seed([seed; 32]).address();
        let account = pouw_types::Account {
            balance: Amount(1_000_000),
            nonce: Nonce(0),
        };
        diff.accounts.insert(
            address,
            Change {
                before: None,
                after: Some(account),
            },
        );
    }
    diff
}

fn with_genesis(h: &mut Harness) -> Block {
    let genesis = genesis_block();
    let id = put(&mut h.state.store, &genesis);
    store::connect_block(&mut h.state.store, &id, &[], &funded()).unwrap();
    genesis
}

fn gossip(h: &mut Harness, message: Gossip) -> MessageId {
    let id = MessageId(h.next_message);
    h.next_message = h.next_message.wrapping_add(1);
    let inbound = Inbound::Gossip {
        id,
        from: peer(),
        message,
    };
    to_node(h, inbound);
    id
}

/// Registers `request` to `peer()` as pending and returns its id.
fn pend(h: &mut Harness, request: SyncRequest) -> RequestId {
    let id = h.state.next_request;
    h.state.next_request = RequestId(id.0.checked_add(1).unwrap());
    h.state.pending.push(PendingRequest {
        id,
        peer: peer(),
        request,
    });
    id
}

/// Queues `block` as the answer of `peer()` to a `GetBlocks` of its id.
fn deliver(h: &mut Harness, block: &Block) {
    let ids = vec![block_id(&block.header)];
    let id = pend(h, SyncRequest::GetBlocks(GetBlocks { ids }));
    let result = Ok(Fetched::Blocks(vec![checked(block.clone())]));
    to_node(h, Inbound::Response { id, result });
}

/// Queues the announcement of `header` by `peer()`.
fn announce(h: &mut Harness, header: BlockHeader) -> MessageId {
    let id = block_id(&header);
    gossip(
        h,
        Gossip::Announce(Box::new(CheckedAnnounce { header, id })),
    )
}

fn drain(h: &mut Harness) -> Vec<Command> {
    let mut commands = Vec::new();
    while let Ok(command) = h.outbound.try_recv() {
        commands.push(command);
    }
    commands
}

fn reports(h: &mut Harness) -> Vec<(PeerIx, Misbehavior)> {
    drain(h)
        .into_iter()
        .filter_map(|command| match command {
            Command::Report(peer, why) => Some((peer, why)),
            _ => None,
        })
        .collect()
}

fn verdicts(h: &mut Harness) -> Vec<(MessageId, Topic, Acceptance)> {
    let mut verdicts = Vec::new();
    while let Ok(command) = h.outbound.try_recv() {
        if let Command::Validate {
            id,
            from,
            topic,
            acceptance,
        } = command
        {
            assert_eq!(from, peer());
            verdicts.push((id, topic, acceptance));
        }
    }
    verdicts
}

fn kinds(log: &EventLog) -> Vec<&'static str> {
    events::page(log, 0, 100)
        .unwrap()
        .events
        .iter()
        .map(|e| e.kind.name())
        .collect()
}

fn tip_height(h: &Harness) -> Option<Height> {
    store::tip(&store::read(&h.state.store).unwrap())
        .unwrap()
        .map(|tip| tip.height)
}

#[test]
fn a_checked_tx_is_pooled_once() {
    let mut h = harness();
    let valid = gossip(&mut h, Gossip::Tx(Box::new(checked_tx(transfer(CHAIN, 0)))));
    let duplicate = gossip(&mut h, Gossip::Tx(Box::new(checked_tx(transfer(CHAIN, 0)))));
    run(&mut h);
    assert_eq!(
        verdicts(&mut h),
        [
            (valid, Topic::CoinTxs, Acceptance::Accept),
            (duplicate, Topic::CoinTxs, Acceptance::Ignore),
        ]
    );
    assert_eq!(h.state.mempool.txs.len(), 1);
    assert_eq!(kinds(&h.state.events), ["tx_received"]);
}

#[test]
fn a_block_on_the_tip_is_connected_and_clears_the_mempool() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let tx = transfer(CHAIN, 0);
    pool(&mut h, tx.clone());
    let child = block(&genesis, vec![tx]);
    let mut wrong_target = test_params().initial_target.0;
    wrong_target[1] = 0xfe;
    let broken = raw_block(
        1,
        block_id(&genesis.header),
        GENESIS_TIME + 1,
        Target(wrong_target),
        vec![],
    );
    let orphan = raw_block(
        5,
        BlockId(Hash32([7; 32])),
        GENESIS_TIME,
        test_params().initial_target,
        vec![],
    );
    for delivered in [&child, &child, &broken, &orphan] {
        deliver(&mut h, delivered);
    }
    run(&mut h);
    assert_eq!(tip_height(&h), Some(Height(1)));
    assert!(h.state.mempool.txs.is_empty());
    assert_eq!(kinds(&h.state.events), ["block_accepted", "block_rejected"]);
    assert_eq!(h.state.metrics.verifications, 2);
    assert_eq!(reports(&mut h), [(peer(), Misbehavior::InvalidBlock)]);
}

#[test]
fn a_child_of_a_failed_block_is_reported_and_stays_unconnected() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let bad = block(&genesis, vec![]);
    let bad_id = put(&mut h.state.store, &bad);
    store::mark_failed(&mut h.state.store, &bad_id).unwrap();
    let child = block(&bad, vec![]);
    let child_id = block_id(&child.header);
    deliver(&mut h, &child);
    run(&mut h);
    assert_eq!(reports(&mut h), [(peer(), Misbehavior::InvalidBlock)]);
    assert_eq!(tip_height(&h), Some(Height(0)));
    let reader = store::read(&h.state.store).unwrap();
    let entry = store::index(&reader, &child_id).unwrap().unwrap();
    assert!(entry.status.contains(store::schema::Status::FAILED));
    assert!(!entry.status.contains(store::schema::Status::CONNECTED));
}

#[test]
fn the_bytes_a_peer_sent_are_the_bytes_stored_and_served() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let child = block(&genesis, vec![transfer(CHAIN, 0)]);
    let id = block_id(&child.header);
    let received = borsh::to_vec(&child).unwrap();
    deliver(&mut h, &child);
    let request = SyncRequest::GetBlocks(GetBlocks { ids: vec![id] });
    to_node(
        &h,
        Inbound::Request {
            from: peer(),
            serve: ServeId(0),
            request,
        },
    );
    run(&mut h);
    assert_eq!(tip_height(&h), Some(Height(1)));
    {
        let reader = store::read(&h.state.store).unwrap();
        let stored = store::block(&reader, &id).unwrap().unwrap();
        assert_eq!(stored.bytes, received.as_slice());
    }
    assert_eq!(
        api::block(&h.state.store, &id).unwrap(),
        Some(received.clone())
    );
    let mut answers = Vec::new();
    for command in drain(&mut h) {
        if let Command::Answer { response, .. } = command {
            answers.push(response);
        }
    }
    assert_eq!(answers, [SyncResponse::Blocks(vec![received])]);
}

#[test]
fn a_sync_request_is_answered_with_a_command_from_the_store() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let child = block(&genesis, vec![]);
    let id = put(&mut h.state.store, &child);
    store::connect_block(&mut h.state.store, &id, &[], &StateDiff::default()).unwrap();
    let requests = [
        SyncRequest::GetHeaders(Box::new(GetHeaders {
            locator: vec![block_id(&genesis.header)],
            stop: None,
        })),
        SyncRequest::GetBlocks(GetBlocks { ids: vec![id] }),
        SyncRequest::GetBlocks(GetBlocks {
            ids: vec![BlockId(Hash32([7; 32]))],
        }),
    ];
    for (serve, request) in (0..).map(ServeId).zip(requests) {
        to_node(
            &h,
            Inbound::Request {
                from: peer(),
                serve,
                request,
            },
        );
    }
    run(&mut h);
    let mut answers = Vec::new();
    for command in drain(&mut h) {
        if let Command::Answer { id, response } = command {
            answers.push((id, response));
        }
    }
    assert_eq!(
        answers,
        [
            (ServeId(0), SyncResponse::Headers(vec![child.header])),
            (
                ServeId(1),
                SyncResponse::Blocks(vec![borsh::to_vec(&child).unwrap()])
            ),
            (ServeId(2), SyncResponse::Blocks(vec![])),
        ]
    );
}

#[test]
fn a_connected_peer_gets_our_status() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    to_node(
        &h,
        Inbound::PeerConnected {
            peer: peer(),
            peer_id: "70".into(),
        },
    );
    run(&mut h);
    let commands = drain(&mut h);
    let [Command::Status { peer: to, status }] = commands.as_slice() else {
        panic!("{commands:?}");
    };
    assert_eq!(*to, peer());
    assert_eq!(status.protocol_version, PROTOCOL_VERSION);
    assert_eq!(status.chain_id, CHAIN);
    assert_eq!(status.genesis, block_id(&genesis.header));
    assert_eq!(status.tip, block_id(&genesis.header));
    assert_eq!(status.height, Height(0));
    assert_eq!(status.services, Services::ARCHIVE);
    assert_eq!(h.state.metrics.peers, 1);
}

#[test]
fn a_peer_response_reaches_its_pending_request_and_an_unknown_id_is_ignored() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let child = block(&genesis, vec![]);
    let ids = vec![block_id(&child.header)];
    let id = pend(&mut h, SyncRequest::GetBlocks(GetBlocks { ids }));
    let unknown = RequestId(id.0.checked_add(100).unwrap());
    for id in [unknown, id] {
        let result = Ok(Fetched::Blocks(vec![checked(child.clone())]));
        to_node(&h, Inbound::Response { id, result });
    }
    run(&mut h);
    assert_eq!(h.state.pending, Vec::new());
    assert_eq!(tip_height(&h), Some(Height(1)));
    assert_eq!(h.state.metrics.verifications, 1);
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap()
}

fn proof_done() -> WorkDone {
    WorkDone::Proof(ProofDone {
        request: TxId(Hash32([4; 32])),
        proof: Ok(Box::from([])),
    })
}

fn some_metrics_request(h: &Harness) {
    let (reply, _) = oneshot::channel();
    to_api(h, ApiRequest::Metrics { reply });
}

/// The next `count` events, with a tick every `every`.
fn next_events(h: &mut Harness, count: usize, every: Duration) -> Vec<Event> {
    runtime().block_on(async {
        let mut tick: Interval = tokio::time::interval(every);
        let mut events = Vec::new();
        for _ in 0..count {
            events.push(node::next_event(&mut h.inbox, &mut tick).await.unwrap());
        }
        events
    })
}

fn name(event: &Event) -> &'static str {
    match event {
        Event::Control(Control::Shutdown) => "shutdown",
        Event::Control(Control::Stopped(..)) => "stopped",
        Event::Work(_) => "work",
        Event::Tick => "tick",
        Event::Net(_) => "p2p",
        Event::Api(_) => "api",
    }
}

#[test]
fn the_loop_takes_control_then_work_then_p2p_then_api_and_the_tick_when_idle() {
    let mut h = harness();
    some_metrics_request(&h);
    to_node(
        &h,
        Inbound::PeerDisconnected {
            peer: peer(),
            peer_id: "70".into(),
        },
    );
    h.feeds.work.try_send(proof_done()).unwrap();
    h.feeds.control.try_send(Control::Shutdown).unwrap();
    let events = next_events(&mut h, 5, node::TICK_INTERVAL);
    let order: Vec<_> = events.iter().map(name).collect();
    assert_eq!(order, ["shutdown", "work", "p2p", "api", "tick"]);
}

#[test]
fn a_due_tick_goes_before_p2p_and_api_and_a_slow_loop_gets_one_tick_not_a_burst() {
    let mut h = harness();
    let every = Duration::from_millis(5);
    let events = runtime().block_on(async {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        assert!(matches!(
            node::next_event(&mut h.inbox, &mut tick).await,
            Ok(Event::Tick)
        ));
        tokio::time::sleep(every * 6).await;
        some_metrics_request(&h);
        to_node(
            &h,
            Inbound::PeerDisconnected {
                peer: peer(),
                peer_id: "70".into(),
            },
        );
        let mut events = Vec::new();
        for _ in 0..3 {
            events.push(node::next_event(&mut h.inbox, &mut tick).await.unwrap());
        }
        events
    });
    let order: Vec<_> = events.iter().map(name).collect();
    assert_eq!(order, ["tick", "p2p", "api"]);
}

#[test]
fn a_shutdown_stops_the_loop_before_the_queued_p2p_and_api_events() {
    let mut h = harness();
    some_metrics_request(&h);
    gossip(&mut h, Gossip::Tx(Box::new(checked_tx(transfer(CHAIN, 0)))));
    h.feeds.control.try_send(Control::Shutdown).unwrap();
    node::run(&mut h.state, &mut h.inbox).unwrap();
    assert!(h.state.mempool.txs.is_empty());
    assert!(h.inbox.p2p.try_recv().is_ok());
    assert!(h.inbox.api.try_recv().is_ok());
    drop(h.feeds);
    assert!(matches!(
        node::run(&mut h.state, &mut h.inbox),
        Err(NodeFault::InboxClosed)
    ));
}

#[test]
fn a_full_api_channel_answers_busy_and_the_loop_keeps_the_queued_requests() {
    let h = harness();
    for _ in 0..node::API_CAPACITY {
        let (reply, _) = oneshot::channel();
        api::submit(&h.feeds.api, ApiRequest::Mempool { reply }).unwrap();
    }
    let (reply, _) = oneshot::channel();
    assert_eq!(
        api::submit(&h.feeds.api, ApiRequest::Mempool { reply }),
        Err(api::Refused::Busy)
    );
    let mut h = h;
    run(&mut h);
    assert_eq!(
        h.state.metrics.dropped_replies,
        u64::try_from(node::API_CAPACITY).unwrap()
    );
    drop(h.inbox);
    let (reply, _) = oneshot::channel();
    assert_eq!(
        api::submit(&h.feeds.api, ApiRequest::Mempool { reply }),
        Err(api::Refused::NodeGone)
    );
}

#[test]
fn a_full_command_channel_drops_the_verdict_and_the_loop_goes_on() {
    let (network, outbound) = mpsc::channel(1);
    let mut h = harness();
    h.state.network = network;
    h.outbound = outbound;
    let first = gossip(&mut h, Gossip::Tx(Box::new(checked_tx(transfer(CHAIN, 0)))));
    gossip(&mut h, Gossip::Tx(Box::new(checked_tx(transfer(CHAIN, 1)))));
    run(&mut h);
    assert_eq!(h.state.mempool.txs.len(), 2);
    assert_eq!(h.state.metrics.dropped_commands, 1);
    assert_eq!(
        verdicts(&mut h),
        [(first, Topic::CoinTxs, Acceptance::Accept)]
    );
}

#[test]
fn a_request_the_full_command_channel_dropped_is_not_left_pending() {
    let (network, outbound) = mpsc::channel(1);
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    h.state.network = network;
    h.outbound = outbound;
    for txs in [vec![], vec![transfer(CHAIN, 0)]] {
        announce(&mut h, block(&genesis, txs).header);
    }
    run(&mut h);
    assert_eq!(h.state.pending.len(), 1);
    assert_eq!(h.state.metrics.dropped_commands, 3);
    assert!(h.state.pending.iter().all(|waiting| waiting.peer == peer()));
}

#[test]
fn an_event_is_small() {
    let size = std::mem::size_of::<Event>();
    assert!(size <= node::MAX_EVENT_BYTES, "Event is {size} bytes");
    assert!(std::mem::size_of::<Inbound>() <= node::MAX_EVENT_BYTES);
    assert!(std::mem::size_of::<ApiRequest>() <= node::MAX_EVENT_BYTES);
    assert!(std::mem::size_of::<Gossip>() <= 16);
}

#[test]
fn a_tick_refreshes_the_gauges() {
    let mut h = harness();
    with_genesis(&mut h);
    pool(&mut h, transfer(CHAIN, 0));
    node::on_tick(&mut h.state).unwrap();
    assert_eq!(h.state.metrics.height, 0);
    assert_eq!(h.state.metrics.mempool_size, 1);
}

#[test]
fn api_reads_are_answered_from_the_store() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let id = block_id(&genesis.header);
    let (tip, tip_answer) = oneshot::channel();
    let (header, mut header_answer) = oneshot::channel();
    let (block, mut block_answer) = oneshot::channel();
    let (account, mut account_answer) = oneshot::channel();
    let (metrics, mut metrics_answer) = oneshot::channel();
    for request in [
        ApiRequest::Tip { reply: tip },
        ApiRequest::Header { id, reply: header },
        ApiRequest::Block { id, reply: block },
        ApiRequest::Account {
            address: Address([2; 32]),
            reply: account,
        },
        ApiRequest::Metrics { reply: metrics },
    ] {
        to_api(&h, request);
    }
    run(&mut h);
    let mut tip_answer = tip_answer;
    assert_eq!(tip_answer.try_recv().unwrap().unwrap().unwrap().id, id);
    assert_eq!(
        header_answer.try_recv().unwrap().unwrap(),
        Some(HeaderView::from(&genesis.header))
    );
    assert_eq!(
        block_answer.try_recv().unwrap().unwrap(),
        Some(borsh::to_vec(&genesis).unwrap())
    );
    assert_eq!(account_answer.try_recv().unwrap().unwrap(), None);
    assert!(
        metrics_answer
            .try_recv()
            .unwrap()
            .contains("pouw_node_height 0")
    );
}

#[test]
fn a_submitted_tx_is_broadcast_only_when_pooled() {
    let mut h = harness();
    let (first, mut first_answer) = oneshot::channel();
    let (again, mut again_answer) = oneshot::channel();
    for reply in [first, again] {
        let checked = submitted(transfer(CHAIN, 0));
        to_api(&h, ApiRequest::SubmitTx { checked, reply });
    }
    run(&mut h);
    assert!(matches!(first_answer.try_recv(), Ok(TxOutcome::Pooled(_))));
    assert!(matches!(again_answer.try_recv(), Ok(TxOutcome::Refused(_))));
    assert!(matches!(
        h.outbound.try_recv(),
        Ok(Command::Broadcast(Gossip::Tx(tx))) if tx.tx == transfer(CHAIN, 0)
    ));
    assert!(h.outbound.try_recv().is_err());
}

#[test]
fn a_submitted_tx_of_another_chain_is_rejected_and_not_broadcast() {
    let mut h = harness();
    let (reply, mut answer) = oneshot::channel();
    let checked = submitted(transfer(ChainId(CHAIN.0 + 1), 0));
    to_api(&h, ApiRequest::SubmitTx { checked, reply });
    run(&mut h);
    assert!(matches!(answer.try_recv(), Ok(TxOutcome::Invalid(_))));
    assert!(h.outbound.try_recv().is_err());
    assert!(h.state.mempool.txs.is_empty());
    assert_eq!(kinds(&h.state.events), ["tx_rejected"]);
}

#[test]
fn a_peer_that_answers_with_an_invalid_block_is_reported() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let mut wrong_target = test_params().initial_target.0;
    wrong_target[1] = 0xfe;
    let broken = raw_block(
        1,
        block_id(&genesis.header),
        GENESIS_TIME + 1,
        Target(wrong_target),
        vec![],
    );
    deliver(&mut h, &broken);
    run(&mut h);
    assert_eq!(reports(&mut h), [(peer(), Misbehavior::InvalidBlock)]);
}

#[test]
fn the_event_log_and_the_tx_index_are_served_to_the_api() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let tx = transfer(CHAIN, 0);
    let id = pouw_types::txid(&tx);
    let child = block(&genesis, vec![tx]);
    deliver(&mut h, &child);
    let (events, mut events_answer) = oneshot::channel();
    let (beyond, mut beyond_answer) = oneshot::channel();
    let (location, mut location_answer) = oneshot::channel();
    for request in [
        ApiRequest::Events {
            after: 0,
            limit: 10,
            reply: events,
        },
        ApiRequest::Events {
            after: u64::MAX,
            limit: 10,
            reply: beyond,
        },
        ApiRequest::TxLocation {
            id,
            reply: location,
        },
    ] {
        to_api(&h, request);
    }
    run(&mut h);
    let page = events_answer.try_recv().unwrap().unwrap();
    assert_eq!(page.next, 1);
    assert_eq!(page.events[0].kind.name(), "block_accepted");
    let beyond = beyond_answer.try_recv().unwrap().unwrap();
    assert_eq!((beyond.events.len(), beyond.next), (0, u64::MAX));
    let location = location_answer.try_recv().unwrap().unwrap().unwrap();
    assert_eq!(location.block, block_id(&child.header));
    assert_eq!(location.height, Height(1));
}

#[test]
fn a_heavier_side_branch_replaces_the_tip_and_returns_the_orphaned_txs() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let (old_tx, new_tx) = (transfer(CHAIN, 0), transfer_from(7, CHAIN, 0));
    let old_tip = block(&genesis, vec![old_tx.clone()]);
    let side = block(&genesis, vec![new_tx.clone()]);
    let side_id = block_id(&side.header);
    let heavier = block(&side, vec![]);
    pool(&mut h, new_tx.clone());
    for delivered in [&old_tip, &side, &heavier] {
        deliver(&mut h, delivered);
    }
    run(&mut h);
    assert_eq!(reports(&mut h), Vec::new());
    let reader = store::read(&h.state.store).unwrap();
    let tip = store::tip(&reader).unwrap().unwrap();
    assert_eq!(tip.id, block_id(&heavier.header));
    let work = |block: &Block| block_work(&block.header.target).0;
    let expected = work(&genesis)
        .checked_add(work(&side))
        .and_then(|sum| sum.checked_add(work(&heavier)));
    assert_eq!(Some(tip.cumulative_work.0), expected);
    assert_eq!(
        store::canonical_id(&reader, Height(1)).unwrap(),
        Some(side_id)
    );
    assert!(
        store::tx_location(&reader, &txid(&old_tx))
            .unwrap()
            .is_none()
    );
    assert!(
        store::tx_location(&reader, &txid(&new_tx))
            .unwrap()
            .is_some()
    );
    assert!(mempool::get(&h.state.mempool, &txid(&old_tx)).is_some());
    assert_eq!(h.state.mempool.txs.len(), 1);
    assert_eq!(
        kinds(&h.state.events),
        [
            "block_accepted",
            "block_orphaned",
            "block_accepted",
            "block_accepted"
        ]
    );
}

#[test]
fn the_api_reads_the_mempool_and_a_tick_snapshots_it() {
    let mut h = harness();
    with_genesis(&mut h);
    let request = TxKind::ProofRequest {
        circuit: CircuitId(TxId(Hash32([3; 32]))),
        public_inputs: vec![],
        witness: Box::from([]),
    };
    let transfer = transfer(CHAIN, 0);
    let proof_request = signed(1, request);
    pool(&mut h, transfer.clone());
    pool(&mut h, proof_request);
    let (reply, mut view) = oneshot::channel();
    to_api(&h, ApiRequest::Mempool { reply });
    run(&mut h);
    for _ in 0..node::SNAPSHOT_EVERY_TICKS {
        node::on_tick(&mut h.state).unwrap();
    }
    let view = view.try_recv().unwrap();
    assert_eq!((view.tx_count, view.proof_request_count), (2, 1));
    assert_eq!(view.txids.len(), 2);
    assert_eq!(kinds(&h.state.events), ["mempool_snapshot"]);
    let page = events::page(&h.state.events, 0, 10).unwrap();
    let EventKind::MempoolSnapshot(snapshot) = &page.events[0].kind else {
        panic!("not a snapshot");
    };
    assert_eq!(
        (snapshot.pending_txs, snapshot.pending_proof_requests),
        (2, 1)
    );
    assert_eq!(snapshot.by_circuit.len(), 1);
}

/// Runs the loop with a shutdown that follows the events of the test, so a fault that
/// is swallowed ends the loop with `Ok` and fails the test instead of blocking it.
fn run_until_fault(h: &mut Harness) -> NodeFault {
    run_loop(h).expect_err("the loop should stop on a fault")
}

#[test]
fn a_store_write_that_fails_stops_the_loop_with_the_store_fault() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let tip = block(&genesis, vec![transfer(CHAIN, 0)]);
    let tip_id = put(&mut h.state.store, &tip);
    store::connect_block(
        &mut h.state.store,
        &tip_id,
        &txids(&tip),
        &StateDiff::default(),
    )
    .unwrap();
    let store::Store::Mem(mem) = &mut h.state.store else {
        panic!("the harness uses the memory store");
    };
    mem.undo.clear();
    let side = block(&genesis, vec![transfer(CHAIN, 1)]);
    let heavier = block(&side, vec![]);
    deliver(&mut h, &side);
    deliver(&mut h, &heavier);
    gossip(&mut h, Gossip::Tx(Box::new(checked_tx(transfer(CHAIN, 2)))));
    let fault = run_until_fault(&mut h);
    assert!(matches!(
        fault,
        NodeFault::Store(store::StoreError::Corrupt(_))
    ));
    assert!(h.state.mempool.txs.is_empty());
}

#[test]
fn a_reply_to_a_caller_that_left_is_counted_and_exported() {
    let mut h = harness();
    let (gone, tip_answer) = oneshot::channel();
    drop(tip_answer);
    let (metrics, mut text) = oneshot::channel();
    for request in [
        ApiRequest::Tip { reply: gone },
        ApiRequest::Metrics { reply: metrics },
    ] {
        to_api(&h, request);
    }
    run(&mut h);
    assert_eq!(h.state.metrics.dropped_replies, 1);
    assert!(
        text.try_recv()
            .unwrap()
            .contains("pouw_node_dropped_replies_total 1\n")
    );
}

#[test]
fn a_component_that_fails_stops_the_loop_and_one_that_finishes_does_not() {
    let mut h = harness();
    for stopped in [
        Control::Stopped(Component::Api, Ok(())),
        Control::Stopped(Component::P2p, Err(ComponentFault::NodeGone)),
    ] {
        h.feeds.control.try_send(stopped).unwrap();
    }
    gossip(&mut h, Gossip::Tx(Box::new(checked_tx(transfer(CHAIN, 0)))));
    assert!(matches!(
        run_until_fault(&mut h),
        NodeFault::Component {
            component: Component::P2p,
            source: ComponentFault::NodeGone,
        }
    ));
    assert!(h.inbox.p2p.try_recv().is_ok());
}

#[test]
fn a_transport_that_is_gone_is_a_fault_not_a_warning() {
    let mut h = harness();
    drop(std::mem::replace(&mut h.outbound, mpsc::channel(1).1));
    let (reply, mut answer) = oneshot::channel();
    to_api(
        &h,
        ApiRequest::SubmitTx {
            checked: submitted(transfer(CHAIN, 0)),
            reply,
        },
    );
    assert!(matches!(
        run_until_fault(&mut h),
        NodeFault::TransportGone(_)
    ));
    assert!(answer.try_recv().is_err());
}

#[test]
fn a_new_peer_with_no_transport_is_a_fault() {
    let mut h = harness();
    with_genesis(&mut h);
    drop(std::mem::replace(&mut h.outbound, mpsc::channel(1).1));
    to_node(
        &h,
        Inbound::PeerConnected {
            peer: peer(),
            peer_id: "70".into(),
        },
    );
    assert!(matches!(
        run_until_fault(&mut h),
        NodeFault::TransportGone(_)
    ));
}

#[test]
fn an_exhausted_event_log_is_a_fault() {
    let mut h = harness();
    h.state.events.last_seq = u64::MAX;
    gossip(&mut h, Gossip::Tx(Box::new(checked_tx(transfer(CHAIN, 0)))));
    assert!(matches!(run_until_fault(&mut h), NodeFault::EventSeq(_)));
}

#[test]
fn a_late_answer_is_reported_to_the_transport() {
    let mut h = harness();
    with_genesis(&mut h);
    let id = pend(&mut h, SyncRequest::GetBlocks(GetBlocks { ids: vec![] }));
    let result = Err(crate::p2p::NetworkError::Timeout);
    to_node(&h, Inbound::Response { id, result });
    run(&mut h);
    assert_eq!(reports(&mut h), [(peer(), Misbehavior::Unresponsive)]);
}

#[test]
fn a_chain_longer_than_the_timestamp_window_connects_block_by_block() {
    let mut h = harness();
    let mut tip = with_genesis(&mut h);
    for _ in 0..14 {
        tip = block(&tip, vec![]);
        deliver(&mut h, &tip);
    }
    run(&mut h);
    assert_eq!(tip_height(&h), Some(Height(14)));
    assert_eq!(reports(&mut h), Vec::new());
}

#[test]
fn a_block_whose_timestamp_breaks_a_rule_is_reported() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let mut at_median = block(&genesis, vec![]);
    at_median.header.timestamp = U64::new(GENESIS_TIME);
    let mut too_far = block(&genesis, vec![]);
    too_far.header.timestamp = U64::new(u64::MAX / 2);
    deliver(&mut h, &remine(at_median));
    deliver(&mut h, &remine(too_far));
    run(&mut h);
    assert_eq!(
        reports(&mut h),
        [
            (peer(), Misbehavior::InvalidBlock),
            (peer(), Misbehavior::InvalidBlock),
        ]
    );
    assert_eq!(tip_height(&h), Some(Height(0)));
}

#[test]
fn a_branch_over_a_block_failed_after_its_child_arrived_is_reported() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let tip_one = block(&genesis, vec![transfer(CHAIN, 0)]);
    let tip_two = block(&tip_one, vec![]);
    let bad = block(&genesis, vec![transfer(CHAIN, 1)]);
    let bad_id = block_id(&bad.header);
    let stored_child = block(&bad, vec![]);
    let heavier = block(&stored_child, vec![]);
    for stored in [&tip_one, &tip_two, &bad, &stored_child] {
        deliver(&mut h, stored);
    }
    run(&mut h);
    drain(&mut h);
    store::mark_failed(&mut h.state.store, &bad_id).unwrap();
    deliver(&mut h, &heavier);
    run(&mut h);
    assert_eq!(reports(&mut h), [(peer(), Misbehavior::InvalidBlock)]);
    let reader = store::read(&h.state.store).unwrap();
    assert_eq!(
        store::tip(&reader).unwrap().map(|tip| tip.id),
        Some(block_id(&tip_two.header))
    );
    let entry = store::index(&reader, &block_id(&stored_child.header))
        .unwrap()
        .unwrap();
    assert!(entry.status.contains(store::schema::Status::FAILED));
}

#[test]
fn an_announce_is_asked_for_when_its_parent_is_indexed_and_headers_when_not() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let genesis_id = block_id(&genesis.header);
    let child = block(&genesis, vec![]);
    let child_id = block_id(&child.header);
    let orphan = raw_block(
        5,
        BlockId(Hash32([7; 32])),
        GENESIS_TIME,
        test_params().initial_target,
        vec![],
    );
    let wrong_height = raw_block(
        5,
        genesis_id,
        GENESIS_TIME,
        test_params().initial_target,
        vec![],
    );
    let accepted = announce(&mut h, child.header);
    let known = announce(&mut h, child.header);
    let unknown = announce(&mut h, orphan.header);
    let rejected = announce(&mut h, wrong_height.header);
    run(&mut h);
    let commands = drain(&mut h);
    let [
        Command::Request {
            peer: asked_block,
            request: SyncRequest::GetBlocks(blocks),
            ..
        },
        Command::Validate {
            id: first,
            topic: Topic::BlockAnnounce,
            acceptance: Acceptance::Accept,
            ..
        },
        Command::Validate {
            id: second,
            acceptance: Acceptance::Ignore,
            ..
        },
        Command::Request {
            peer: asked_headers,
            request: SyncRequest::GetHeaders(headers),
            ..
        },
        Command::Validate {
            id: third,
            acceptance: Acceptance::Ignore,
            ..
        },
        Command::Validate {
            id: fourth,
            acceptance: Acceptance::Reject,
            ..
        },
    ] = commands.as_slice()
    else {
        panic!("{commands:?}");
    };
    assert_eq!(
        (*first, *second, *third, *fourth),
        (accepted, known, unknown, rejected)
    );
    assert_eq!((*asked_block, *asked_headers), (peer(), peer()));
    assert_eq!(blocks.ids, [child_id]);
    assert_eq!(headers.locator, [genesis_id]);
    assert_eq!(headers.stop, None);
    assert_eq!(h.state.pending.len(), 2);
    let reader = store::read(&h.state.store).unwrap();
    assert!(store::header(&reader, &child_id).unwrap().is_some());
}

#[test]
fn an_announce_that_breaks_a_header_rule_is_rejected_and_not_stored() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let mut harder = test_params().initial_target;
    harder.0[1] = 0x7f;
    let wrong_target = raw_block(
        1,
        block_id(&genesis.header),
        GENESIS_TIME.saturating_add(1),
        harder,
        vec![],
    );
    let second_genesis = raw_block(
        0,
        BlockId::ZERO,
        GENESIS_TIME.saturating_add(1),
        test_params().initial_target,
        vec![],
    );
    let rejected = announce(&mut h, wrong_target.header);
    let rootless = announce(&mut h, second_genesis.header);
    run(&mut h);
    let commands = drain(&mut h);
    let [
        Command::Validate {
            id: first,
            acceptance: Acceptance::Reject,
            ..
        },
        Command::Request {
            request: SyncRequest::GetHeaders(_),
            ..
        },
        Command::Validate {
            id: second,
            acceptance: Acceptance::Ignore,
            ..
        },
    ] = commands.as_slice()
    else {
        panic!("{commands:?}");
    };
    assert_eq!((*first, *second), (rejected, rootless));
    let reader = store::read(&h.state.store).unwrap();
    for header in [&wrong_target.header, &second_genesis.header] {
        assert_eq!(store::index(&reader, &block_id(header)).unwrap(), None);
    }
}

fn status_of(h: &Harness) -> Status {
    node::our_status(&h.state).unwrap()
}

fn status_from_peer(h: &Harness, status: Status) {
    to_node(
        h,
        Inbound::Status {
            from: peer(),
            status: Box::new(status),
        },
    );
}

#[test]
fn a_status_of_another_chain_is_a_disconnect_and_no_penalty() {
    let mut h = harness();
    with_genesis(&mut h);
    let ours = status_of(&h);
    let versions = Status {
        protocol_version: PROTOCOL_VERSION + 1,
        ..ours.clone()
    };
    let chains = Status {
        chain_id: ChainId(CHAIN.0 + 1),
        ..ours.clone()
    };
    let genesis = Status {
        genesis: BlockId(Hash32([7; 32])),
        ..ours
    };
    for status in [versions, chains, genesis] {
        status_from_peer(&h, status);
    }
    run(&mut h);
    let commands = drain(&mut h);
    let [
        Command::Disconnect { reason: first, .. },
        Command::Disconnect { reason: second, .. },
        Command::Disconnect { reason: third, .. },
    ] = commands.as_slice()
    else {
        panic!("{commands:?}");
    };
    assert_eq!(
        [*first, *second, *third],
        [
            DisconnectReason::ProtocolVersion,
            DisconnectReason::ChainId,
            DisconnectReason::Genesis,
        ]
    );
}

#[test]
fn a_status_with_more_work_asks_for_headers_once_and_one_with_less_asks_nothing() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let ours = status_of(&h);
    let more = block_work(&test_params().initial_target).0;
    let heavier = Status {
        cumulative_work: CumWork(ours.cumulative_work.0.checked_add(more).unwrap()),
        height: Height(5),
        ..ours.clone()
    };
    status_from_peer(&h, ours);
    run(&mut h);
    assert!(drain(&mut h).is_empty());
    status_from_peer(&h, heavier.clone());
    status_from_peer(&h, heavier);
    run(&mut h);
    let commands = drain(&mut h);
    let [
        Command::Request {
            peer: asked,
            request: SyncRequest::GetHeaders(get),
            ..
        },
    ] = commands.as_slice()
    else {
        panic!("{commands:?}");
    };
    assert_eq!(*asked, peer());
    assert_eq!(get.locator, [block_id(&genesis.header)]);
}

const MINER: Address = Address([5; 32]);
const CIRCUIT: &[u8] = b"circuit";

fn circuit_id() -> CircuitId {
    CircuitId(TxId(Hash32([3; 32])))
}

/// Stores genesis and registers [`CIRCUIT`] in the state at genesis.
fn with_circuit(h: &mut Harness) -> Block {
    let genesis = genesis_block();
    let id = put(&mut h.state.store, &genesis);
    let keys = h.prover.setup(CIRCUIT).unwrap();
    let entry = CircuitEntry {
        id: circuit_id(),
        system: ProofSystem::Groth16,
        constraint_count: ConstraintCount(1),
        owner: Address([1; 32]),
        registered_at: Height(0),
        verifying_key: keys.verifying_key,
        circuit: Box::from(CIRCUIT),
    };
    let mut diff = funded();
    let change = Change {
        before: None,
        after: Some(entry),
    };
    diff.circuits.insert(circuit_id(), change);
    store::connect_block(&mut h.state.store, &id, &[], &diff).unwrap();
    genesis
}

fn proof_request(seed: u8, nonce: u64) -> SignedTx {
    let key = SigningKey::from_seed([seed; 32]);
    sign_body(
        &TxBody {
            chain_id: CHAIN,
            sender: key.address(),
            nonce: Nonce(nonce),
            fee: Amount(100),
            kind: TxKind::ProofRequest {
                circuit: circuit_id(),
                public_inputs: vec![],
                witness: Box::from([]),
            },
        },
        &key,
    )
}

fn height_of(h: &Harness) -> u64 {
    tip_height(h).map_or(0, |height| height.0)
}

/// Mines until the tip is at `height`, reading the controlled clock ten seconds per
/// block.
fn mine_to(h: &mut Harness, height: u64) {
    miner::dispatch(&mut h.state).unwrap();
    pump_until(h, |h| {
        let at = height_of(h);
        set_clock(GENESIS_TIME.saturating_add(at.saturating_add(1).saturating_mul(10)));
        at >= height
    })
    .unwrap();
    assert_eq!(height_of(h), height);
}

/// Stops the node from mining and drops the job it had under way.
fn stop_mining(h: &mut Harness) {
    h.state.miner = None;
    while h.jobs.try_recv().is_ok() {}
    h.state.work.in_flight = None;
}

fn canonical_blocks(h: &Harness, heights: std::ops::RangeInclusive<u64>) -> Vec<Block> {
    let reader = store::read(&h.state.store).unwrap();
    heights
        .map(|height| {
            let id = store::canonical_id(&reader, Height(height))
                .unwrap()
                .unwrap();
            let bytes = store::block(&reader, &id).unwrap().unwrap();
            store::decode(&bytes).unwrap()
        })
        .collect()
}

fn announced(h: &mut Harness) -> Vec<BlockId> {
    drain(h)
        .into_iter()
        .filter_map(|command| match command {
            Command::Broadcast(Gossip::Announce(announce)) => Some(announce.id),
            _ => None,
        })
        .collect()
}

#[test]
fn a_miner_mines_blocks_by_fee_rate_with_no_proof_request_and_announces_them() {
    let mut h = harness();
    with_genesis(&mut h);
    h.state.miner = Some(MINER);
    let (cheap, rich) = (transfer_from(7, CHAIN, 0), transfer_from(8, CHAIN, 0));
    let mut rich_tx = rich.clone();
    rich_tx.body.fee = Amount(9);
    let rich_tx = sign_body(&rich_tx.body, &SigningKey::from_seed([8; 32]));
    pool(&mut h, cheap.clone());
    pool(&mut h, rich_tx.clone());
    mine_to(&mut h, 3);
    let blocks = canonical_blocks(&h, 1..=3);
    assert!(blocks.iter().all(|block| block.header.miner == MINER));
    assert!(blocks.iter().all(|block| block.proof_txs.is_empty()));
    assert_eq!(blocks[0].txs, [rich_tx, cheap]);
    assert!(h.state.mempool.txs.is_empty());
    let expected: Vec<_> = blocks.iter().map(|b| block_id(&b.header)).collect();
    assert_eq!(announced(&mut h), expected);
    assert_eq!(reports(&mut h), Vec::new());
}

#[test]
fn a_miner_with_a_pending_request_proves_it_and_mines_the_proof_into_a_block() {
    let mut h = harness();
    with_circuit(&mut h);
    h.state.miner = Some(MINER);
    let request = proof_request(1, 0);
    pool(&mut h, request.clone());
    mine_to(&mut h, 1);
    let mined = canonical_blocks(&h, 1..=1).remove(0);
    let [proof_tx] = mined.proof_txs.as_slice() else {
        panic!("the block carries one proof");
    };
    assert_eq!(proof_tx.request, request);
    assert_eq!(proof_tx.usage_counter, UsageCounter(0));
    assert!(h.state.mempool.txs.is_empty());
    let parent = canonical_blocks(&h, 0..=0).remove(0);
    let etas = eta_chain(
        &block_id(&parent.header),
        &mined.compute_txs_root(),
        &mined.proof_txs,
    );
    let keys = h.prover.setup(CIRCUIT).unwrap();
    let mask = mask(&MINER, &circuit_id(), UsageCounter(0));
    let statement = Statement::new(&etas[0], &mask, &[]);
    assert!(
        h.prover
            .verify(&keys.verifying_key, &statement, &proof_tx.proof)
            .unwrap()
    );
}

#[test]
fn a_request_for_an_unknown_circuit_does_not_keep_the_miner_from_mining() {
    let mut h = harness();
    with_genesis(&mut h);
    h.state.miner = Some(MINER);
    pool(&mut h, proof_request(1, 0));
    mine_to(&mut h, 2);
    assert_eq!(h.state.mempool.txs.len(), 1);
    let blocks = canonical_blocks(&h, 1..=2);
    assert!(blocks.iter().all(|block| block.proof_txs.is_empty()));
}

#[test]
fn the_worker_takes_a_received_block_before_a_proof_and_a_proof_before_a_search() {
    let mut h = harness();
    let genesis = with_circuit(&mut h);
    h.state.miner = Some(MINER);
    pool(&mut h, proof_request(1, 0));
    let first = block(&genesis, vec![]);
    let second = block(&first, vec![]);
    miner::enqueue_verify(&mut h.state, peer(), checked(first)).unwrap();
    miner::enqueue_verify(&mut h.state, peer(), checked(second)).unwrap();
    let mut order = Vec::new();
    for _ in 0..4 {
        let job = h.jobs.try_recv().unwrap();
        order.push(match &job {
            WorkJob::VerifyWork(_) => "verify",
            WorkJob::Prove(_) => "prove",
            WorkJob::SearchNonce(_) => "search",
        });
        let done = miner::run_job(&h.prover, &h.state.params, job);
        node::handle(&mut h.state, Event::Work(done)).unwrap();
    }
    assert_eq!(order, ["verify", "verify", "prove", "search"]);
    assert_eq!(height_of(&h), 3);
}

#[test]
fn a_full_verify_queue_drops_the_block_counts_it_and_does_not_penalise_the_peer() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let received = checked(block(&genesis, vec![]));
    miner::enqueue_verify(&mut h.state, peer(), received.clone()).unwrap();
    for _ in 0..miner::VERIFY_QUEUE_CAP {
        miner::enqueue_verify(&mut h.state, peer(), received.clone()).unwrap();
    }
    assert_eq!(h.state.work.verify_queue.len(), miner::VERIFY_QUEUE_CAP);
    assert_eq!(h.state.metrics.dropped_blocks, 0);
    miner::enqueue_verify(&mut h.state, peer(), received).unwrap();
    assert_eq!(h.state.work.verify_queue.len(), miner::VERIFY_QUEUE_CAP);
    assert_eq!(h.state.metrics.dropped_blocks, 1);
    assert_eq!(reports(&mut h), Vec::new());
}

#[test]
fn two_miners_on_separate_branches_end_on_the_branch_with_more_work() {
    let mut a = harness();
    let mut b = harness();
    with_genesis(&mut a);
    with_genesis(&mut b);
    a.state.miner = Some(MINER);
    b.state.miner = Some(Address([6; 32]));
    let orphaned = transfer_from(7, CHAIN, 0);
    pool(&mut a, orphaned.clone());
    mine_to(&mut a, 2);
    mine_to(&mut b, 3);
    stop_mining(&mut a);
    stop_mining(&mut b);
    let a_blocks = canonical_blocks(&a, 1..=2);
    let b_blocks = canonical_blocks(&b, 1..=3);
    assert_eq!(a_blocks[0].txs, std::slice::from_ref(&orphaned));
    assert_ne!(block_id(&a_blocks[0].header), block_id(&b_blocks[0].header));
    assert!(mempool::get(&a.state.mempool, &txid(&orphaned)).is_none());
    for block in &b_blocks {
        deliver(&mut a, block);
    }
    run(&mut a);
    assert_eq!(reports(&mut a), Vec::new());
    let tip = |h: &Harness| {
        store::tip(&store::read(&h.state.store).unwrap())
            .unwrap()
            .unwrap()
    };
    assert_eq!(tip(&a), tip(&b));
    assert_eq!(tip(&a).height, Height(3));
    assert!(mempool::get(&a.state.mempool, &txid(&orphaned)).is_some());
    assert!(kinds(&a.state.events).contains(&"block_orphaned"));
}

#[test]
fn a_miner_whose_chain_is_ahead_of_the_clock_waits_instead_of_sealing_a_block_that_cannot_connect()
{
    let mut h = harness();
    with_genesis(&mut h);
    h.state.miner = Some(MINER);
    let ahead = h.state.params.max_future_secs.saturating_add(10);
    set_clock(GENESIS_TIME.saturating_sub(ahead));
    miner::dispatch(&mut h.state).unwrap();
    let mut steps = 0;
    pump_until(&mut h, |_| {
        steps += 1;
        steps > 1_000
    })
    .unwrap();
    assert_eq!(height_of(&h), 0);
    assert!(h.state.work.in_flight.is_none());
    set_clock(GENESIS_TIME);
    mine_to(&mut h, 1);
}

fn index_status(h: &Harness, block: &Block) -> store::schema::Status {
    let reader = store::read(&h.state.store).unwrap();
    store::index(&reader, &block_id(&block.header))
        .unwrap()
        .unwrap()
        .status
}

#[test]
fn a_block_the_state_transition_rejects_is_failed_reported_and_not_connected() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let bad = block(&genesis, vec![transfer(CHAIN, 0)]);
    chain::reject_on_connect(Some(block_id(&bad.header)));
    deliver(&mut h, &bad);
    run(&mut h);
    chain::reject_on_connect(None);
    assert_eq!(reports(&mut h), [(peer(), Misbehavior::InvalidBlock)]);
    assert_eq!(tip_height(&h), Some(Height(0)));
    let status = index_status(&h, &bad);
    assert!(status.contains(store::schema::Status::FAILED));
    assert!(!status.contains(store::schema::Status::CONNECTED));
    assert_eq!(kinds(&h.state.events), ["block_rejected"]);
}

#[test]
fn a_reorg_onto_a_branch_with_a_rejected_block_leaves_the_old_chain() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let old_tx = transfer_from(7, CHAIN, 0);
    let a1 = block(&genesis, vec![old_tx.clone()]);
    let b1 = block(&genesis, vec![transfer_from(8, CHAIN, 0)]);
    let b2 = block(&b1, vec![]);
    chain::reject_on_connect(Some(block_id(&b1.header)));
    for delivered in [&a1, &b1, &b2] {
        deliver(&mut h, delivered);
    }
    run(&mut h);
    chain::reject_on_connect(None);
    assert_eq!(reports(&mut h), [(peer(), Misbehavior::InvalidBlock)]);
    let reader = store::read(&h.state.store).unwrap();
    assert_eq!(
        store::tip(&reader).unwrap().map(|tip| tip.id),
        Some(block_id(&a1.header))
    );
    assert!(
        store::tx_location(&reader, &txid(&old_tx))
            .unwrap()
            .is_some()
    );
    for failed in [&b1, &b2] {
        assert!(index_status(&h, failed).contains(store::schema::Status::FAILED));
    }
    assert!(!index_status(&h, &a1).contains(store::schema::Status::FAILED));
    assert!(h.state.mempool.txs.is_empty());
    assert_eq!(
        kinds(&h.state.events),
        [
            "block_accepted",
            "block_orphaned",
            "block_rejected",
            "block_accepted"
        ]
    );
}

#[test]
fn a_reorg_that_connected_part_of_its_branch_returns_to_the_heavier_old_chain() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let a1 = block(&genesis, vec![transfer_from(7, CHAIN, 0)]);
    let a2 = block(&a1, vec![transfer_from(7, CHAIN, 1)]);
    let b1_tx = transfer_from(8, CHAIN, 0);
    let b1 = block(&genesis, vec![b1_tx.clone()]);
    let b2 = block(&b1, vec![transfer_from(8, CHAIN, 1)]);
    let b3 = block(&b2, vec![]);
    chain::reject_on_connect(Some(block_id(&b2.header)));
    for delivered in [&a1, &a2, &b1, &b2, &b3] {
        deliver(&mut h, delivered);
    }
    run(&mut h);
    chain::reject_on_connect(None);
    assert_eq!(reports(&mut h), [(peer(), Misbehavior::InvalidBlock)]);
    let reader = store::read(&h.state.store).unwrap();
    assert_eq!(
        store::tip(&reader).unwrap().map(|tip| tip.id),
        Some(block_id(&a2.header))
    );
    assert_eq!(
        store::canonical_id(&reader, Height(1)).unwrap(),
        Some(block_id(&a1.header))
    );
    for failed in [&b2, &b3] {
        assert!(index_status(&h, failed).contains(store::schema::Status::FAILED));
    }
    assert!(!index_status(&h, &b1).contains(store::schema::Status::FAILED));
    assert_eq!(
        h.state.mempool.txs.keys().collect::<Vec<_>>(),
        [&txid(&b1_tx)]
    );
    assert_eq!(
        kinds(&h.state.events),
        [
            "block_accepted",
            "block_accepted",
            "block_orphaned",
            "block_orphaned",
            "block_accepted",
            "block_rejected",
            "block_orphaned",
            "block_accepted",
            "block_accepted"
        ]
    );
}

#[test]
fn the_miner_runs_candidate_only_when_a_proof_request_is_untried() {
    let mut h = harness();
    with_genesis(&mut h);
    h.state.miner = Some(MINER);
    pool(&mut h, transfer_from(7, CHAIN, 0));
    pool(&mut h, transfer_from(8, CHAIN, 0));
    let before = miner::candidate_calls();
    miner::dispatch(&mut h.state).unwrap();
    let template_only = miner::candidate_calls() - before;
    assert_eq!(template_only, 1);
    stop_mining(&mut h);
    h.state.work.template = None;
    h.state.miner = Some(MINER);
    pool(&mut h, proof_request(9, 0));
    let before = miner::candidate_calls();
    miner::dispatch(&mut h.state).unwrap();
    assert!(miner::candidate_calls() - before > template_only);
}
