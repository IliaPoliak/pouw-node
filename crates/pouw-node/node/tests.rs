use std::{
    cell::Cell,
    collections::{BTreeSet, VecDeque},
    time::Duration,
};

use pouw_api::{
    event::EventKind,
    view::{HeaderView, TxStatus},
};
use pouw_consensus::{Anchor, Change, InvalidTx, Scratch, StateDiff, next_target};
use pouw_crypto::{Address, Hash32, SigningKey};
use pouw_provers::{MockProver, Prover, Statement};
use pouw_types::{
    Amount, Block, BlockHeader, BlockId, ChainId, CircuitEntry, CircuitId, ConsensusParams,
    ConstraintCount, CumWork, Height, Nonce, ProofSystem, SignedTx, SystemId, Target, Timestamp,
    TxBody, TxId, TxKind, U32, U64, U256, UsageCounter, block_id, block_work, eta_chain, mask,
    proof_tx_hash, sign_body, txid, verify_inclusion,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::Interval,
};

use crate::{
    api::{self, ApiRequest, BlockKey, BlockQuery, BlockReply, Ranged, TxReply},
    chain::{self, TxOutcome},
    events::{self, EventLog},
    ibd::Ibd,
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
    sync::{self, PendingRequest},
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
        prover: pouw_provers::Prover::from(pouw_provers::MockProver::default()),
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
        ibd: Ibd::default(),
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
    with_genesis(&mut h);
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
        assert_eq!(stored.bytes.as_ref(), received.as_slice());
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
    with_genesis(&mut h);
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
    with_genesis(&mut h);
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
    with_genesis(&mut h);
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

#[test]
fn the_canonical_chain_is_served_by_key_and_by_range() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let child = block(&genesis, vec![]);
    deliver(&mut h, &child);
    let (genesis_id, child_id) = (block_id(&genesis.header), block_id(&child.header));
    let unknown = pouw_types::BlockId(Hash32([7; 32]));

    let (head, mut head_answer) = oneshot::channel();
    let (genesis_view, mut genesis_view_answer) = oneshot::channel();
    let (by_id, mut by_id_answer) = oneshot::channel();
    let (nobody, mut nobody_answer) = oneshot::channel();
    let (header, mut header_answer) = oneshot::channel();
    let (blocks, mut blocks_answer) = oneshot::channel();
    let (headers, mut headers_answer) = oneshot::channel();
    let (beyond, mut beyond_answer) = oneshot::channel();
    let (reversed, mut reversed_answer) = oneshot::channel();
    let (node, mut node_answer) = oneshot::channel();
    let query =
        |key, json, reply| ApiRequest::CanonicalBlock(Box::new(BlockQuery { key, json, reply }));
    for request in [
        query(BlockKey::Head, false, head),
        query(BlockKey::Height(Height(0)), true, genesis_view),
        query(BlockKey::Id(child_id), false, by_id),
        query(BlockKey::Id(unknown), false, nobody),
        ApiRequest::CanonicalHeader {
            key: BlockKey::Height(Height(1)),
            reply: header,
        },
        ApiRequest::Blocks {
            from: None,
            to: None,
            json: false,
            reply: blocks,
        },
        ApiRequest::Headers {
            from: Some(1),
            to: None,
            reply: headers,
        },
        ApiRequest::Headers {
            from: Some(5),
            to: None,
            reply: beyond,
        },
        ApiRequest::Headers {
            from: Some(1),
            to: Some(0),
            reply: reversed,
        },
        ApiRequest::Node { reply: node },
    ] {
        to_api(&h, request);
    }
    run(&mut h);

    let child_bytes = borsh::to_vec(&child).unwrap();
    assert_eq!(
        head_answer.try_recv().unwrap().unwrap(),
        Some(BlockReply::Bytes(child_bytes.clone()))
    );
    let Some(BlockReply::View(view)) = genesis_view_answer.try_recv().unwrap().unwrap() else {
        panic!("the genesis is not a view");
    };
    assert_eq!(view.id, genesis_id);
    assert_eq!(
        by_id_answer.try_recv().unwrap().unwrap(),
        Some(BlockReply::Bytes(child_bytes.clone()))
    );
    assert_eq!(nobody_answer.try_recv().unwrap().unwrap(), None);
    assert_eq!(
        header_answer.try_recv().unwrap().unwrap().unwrap().id,
        child_id
    );
    let Ranged::Items(items) = blocks_answer.try_recv().unwrap().unwrap() else {
        panic!("the blocks are not items");
    };
    assert_eq!(items.len(), 2);
    assert_eq!(items[1], BlockReply::Bytes(child_bytes));
    let Ranged::Items(found) = headers_answer.try_recv().unwrap().unwrap() else {
        panic!("the headers are not items");
    };
    assert_eq!(found.len(), 1);
    assert_eq!(
        beyond_answer.try_recv().unwrap().unwrap(),
        Ranged::Items(Vec::new())
    );
    assert_eq!(
        reversed_answer.try_recv().unwrap().unwrap(),
        Ranged::FromAboveTo
    );
    let info = node_answer.try_recv().unwrap().unwrap();
    assert_eq!((info.chain_id, info.height), (CHAIN, Height(1)));
}

#[test]
fn a_block_with_a_proof_is_served_with_its_derived_fields() {
    let mut h = harness();
    with_circuit(&mut h);
    h.state.miner = Some(MINER);
    pool(&mut h, proof_request(1, 0));
    mine_to(&mut h, 1);
    h.state.miner = None;
    let mined = canonical_blocks(&h, 1..=1).remove(0);
    let parent = canonical_blocks(&h, 0..=0).remove(0);

    let (reply, mut answer) = oneshot::channel();
    let query = BlockQuery {
        key: BlockKey::Height(Height(1)),
        json: true,
        reply,
    };
    to_api(&h, ApiRequest::CanonicalBlock(Box::new(query)));
    run(&mut h);
    let Some(BlockReply::View(view)) = answer.try_recv().unwrap().unwrap() else {
        panic!("the block is not a view");
    };
    let etas = eta_chain(
        &block_id(&parent.header),
        &mined.compute_txs_root(),
        &mined.proof_txs,
    );
    let [proof] = view.proof_txs.as_slice() else {
        panic!("the block carries one proof");
    };
    assert_eq!(proof.eta, pouw_crypto::hash_to_field(&etas[0]));
    let mask = mask(&MINER, &circuit_id(), UsageCounter(0));
    assert_eq!(proof.mask, pouw_crypto::hash_to_field(&mask));
    assert_eq!(proof.proof_system, h.prover.id());
    assert_eq!(proof.request_txid, pouw_types::txid(&proof_request(1, 0)));
    assert_eq!(view.id, block_id(&mined.header));
}

/// What `POST /v1/txs` answers for `tx` when the loop is the real one: the handler is a
/// task of a runtime on this thread, and the loop handles each request it queues.
fn post_to_node(h: &mut Harness, tx: &SignedTx) -> (axum::http::StatusCode, serde_json::Value) {
    let runtime = runtime();
    let body = axum::body::Bytes::from(borsh::to_vec(tx).unwrap());
    let call = runtime.spawn(crate::http::post_tx(h.feeds.api.clone(), body));
    while !call.is_finished() {
        runtime.block_on(tokio::task::yield_now());
        run(h);
    }
    let (status, body) = runtime.block_on(call).unwrap();
    (status, serde_json::from_slice(&body).unwrap_or_default())
}

#[test]
fn post_txs_runs_the_admission_check_against_the_state_of_the_node() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);

    // signed, on this chain, but more than the 1_000_000 of the sender
    let broke = signed(
        0,
        TxKind::Transfer {
            to: Address([2; 32]),
            amount: Amount(2_000_000),
        },
    );
    let (status, answer) = post_to_node(&mut h, &broke);
    assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(answer["error"]["code"], "insufficient_balance");
    assert!(h.state.mempool.txs.is_empty());
    assert_eq!(kinds(&h.state.events), ["tx_rejected"]);

    // the same sender with a fair one is pooled
    let fair = transfer(CHAIN, 0);
    let (status, answer) = post_to_node(&mut h, &fair);
    assert_eq!(status, axum::http::StatusCode::ACCEPTED);
    assert_eq!(answer["txid"], serde_json::json!(txid(&fair)));
    assert_eq!(h.state.mempool.txs.len(), 1);

    // once a block holds it, its nonce is stale
    deliver(&mut h, &block(&genesis, vec![fair.clone()]));
    run(&mut h);
    assert_eq!(tip_height(&h), Some(Height(1)));
    assert!(h.state.mempool.txs.is_empty());
    let (status, answer) = post_to_node(&mut h, &fair);
    assert_eq!(status, axum::http::StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(answer["error"]["code"], "bad_nonce");
    assert!(h.state.mempool.txs.is_empty());
}

/// Asks the loop one question and returns its answer.
fn ask_api<T>(h: &mut Harness, request: impl FnOnce(oneshot::Sender<T>) -> ApiRequest) -> T {
    let (reply, mut answer) = oneshot::channel();
    to_api(h, request(reply));
    run(h);
    answer.try_recv().unwrap()
}

#[test]
fn a_tx_its_inclusion_proof_and_the_circuits_are_served_from_the_store() {
    let mut h = harness();
    with_circuit(&mut h);
    h.state.miner = Some(MINER);
    let request = proof_request(1, 0);
    pool(&mut h, request.clone());
    mine_to(&mut h, 1);
    h.state.miner = None;
    let mined = canonical_blocks(&h, 1..=1).remove(0);
    let included = txid(&request);
    let queued = proof_request(2, 0);
    let queued_id = txid(&queued);
    pool(&mut h, queued.clone());
    let unknown = TxId(Hash32([0xee; 32]));
    let at = mined.txs.len();
    let leaf = u32::try_from(at).unwrap();

    let tx = |h: &mut Harness, id: TxId, json: bool| {
        ask_api(h, |reply| ApiRequest::Tx { id, json, reply }).unwrap()
    };
    // an included proof request: its bytes, then the view with the fields of its proof tx
    assert_eq!(
        tx(&mut h, included, false),
        Some(TxReply::Bytes(borsh::to_vec(&request).unwrap()))
    );
    let Some(TxReply::View(view)) = tx(&mut h, included, true) else {
        panic!("the included tx is not a view");
    };
    assert!(matches!(view.status, TxStatus::Included));
    assert_eq!(
        (view.txid, view.height, view.index),
        (included, Some(Height(1)), Some(leaf))
    );
    let proof = view.proof.expect("an included proof request has its proof");
    let stored = &mined.proof_txs[0];
    assert_eq!(proof.proof_hash, proof_tx_hash(stored));
    assert_eq!(proof.usage_counter, stored.usage_counter);
    assert_eq!(proof.proof, stored.proof);
    assert_eq!(proof.proof_system, h.prover.id());
    // a queued one is pending, in both forms, and an unknown one is nothing
    let Some(TxReply::View(view)) = tx(&mut h, queued_id, true) else {
        panic!("the pending tx is not a view");
    };
    assert!(matches!(view.status, TxStatus::Pending));
    assert_eq!((view.height, view.index), (None, None));
    assert!(view.proof.is_none());
    assert_eq!(
        tx(&mut h, queued_id, false),
        Some(TxReply::Bytes(borsh::to_vec(&queued).unwrap()))
    );
    assert_eq!(tx(&mut h, unknown, true), None);

    // the inclusion proof verifies against the header of the block
    let inclusion = |h: &mut Harness, id: TxId| {
        ask_api(h, |reply| ApiRequest::Inclusion { id, reply }).unwrap()
    };
    let path = inclusion(&mut h, included).expect("an included tx has an inclusion proof");
    let leaves = mined.leaf_ids();
    assert_eq!(
        (path.height, path.index, path.leaf_count),
        (Height(1), leaf, u32::try_from(leaves.len()).unwrap())
    );
    assert!(verify_inclusion(
        &mined.header.tx_root,
        &leaves[at],
        path.index,
        path.leaf_count,
        &path.siblings
    ));
    assert_eq!(inclusion(&mut h, queued_id), None);
    assert_eq!(inclusion(&mut h, unknown), None);

    // the registry: the one circuit, without and with its blobs
    let circuits = |h: &mut Harness, keys: bool| {
        ask_api(h, |reply| ApiRequest::Circuits { keys, reply }).unwrap()
    };
    let [entry] = circuits(&mut h, false).try_into().unwrap_or_else(|_| {
        panic!("one circuit is registered");
    });
    assert_eq!((entry.id, entry.registered_at), (circuit_id(), Height(0)));
    assert!(entry.verifying_key.is_none() && entry.circuit.is_none());
    let [keyed] = circuits(&mut h, true).try_into().unwrap_or_else(|_| {
        panic!("one circuit is registered");
    });
    assert_eq!(keyed.circuit.as_deref(), Some(CIRCUIT));
    let one = ask_api(&mut h, |reply| ApiRequest::Circuit {
        id: circuit_id(),
        keys: true,
        reply,
    })
    .unwrap()
    .expect("the circuit is registered");
    assert_eq!(one, keyed);
    let missing = ask_api(&mut h, |reply| ApiRequest::Circuit {
        id: CircuitId(unknown),
        keys: false,
        reply,
    })
    .unwrap();
    assert_eq!(missing, None);
}

#[cfg(feature = "rocksdb")]
#[test]
fn the_circuits_of_a_rocksdb_store_are_listed_by_registration_and_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("pouw-node-{}-circuits", std::process::id()));
    drop(std::fs::remove_dir_all(&dir));
    let open = || store::open(crate::config::StoreKind::Rocksdb, &dir).unwrap();
    let listed = |store: &store::Store| {
        store::circuits(&store::read(store).unwrap())
            .unwrap()
            .iter()
            .map(|entry| (entry.id, entry.registered_at))
            .collect::<Vec<_>>()
    };

    let mut h = harness();
    h.state.store = open();
    let genesis = with_circuit(&mut h);
    // a second circuit, registered one block later, with an id that sorts before the first
    let [first] = store::circuits(&store::read(&h.state.store).unwrap())
        .unwrap()
        .try_into()
        .unwrap_or_else(|_| panic!("one circuit is registered"));
    let second = CircuitEntry {
        id: CircuitId(TxId(Hash32([2; 32]))),
        registered_at: Height(1),
        ..first.clone()
    };
    let child = block(&genesis, vec![]);
    let child_id = put(&mut h.state.store, &child);
    let mut diff = StateDiff::default();
    diff.circuits.insert(
        second.id,
        Change {
            before: None,
            after: Some(second.clone()),
        },
    );
    store::connect_block(&mut h.state.store, &child_id, &[], &diff).unwrap();

    // the API lists them, by height of registration and not by id
    let expected = [(first.id, Height(0)), (second.id, Height(1))];
    let ids = |h: &mut Harness, keys: bool| {
        ask_api(h, |reply| ApiRequest::Circuits { keys, reply })
            .unwrap()
            .iter()
            .map(|view| (view.id, view.registered_at))
            .collect::<Vec<_>>()
    };
    assert_eq!(ids(&mut h, false), expected);
    let keyed = ask_api(&mut h, |reply| ApiRequest::Circuits { keys: true, reply }).unwrap();
    assert_eq!(keyed[0].circuit.as_deref(), Some(CIRCUIT));

    // the registry is read back from the files
    h.state.store = store::memory();
    let reopened = open();
    assert_eq!(listed(&reopened), expected);
}

// Initial block download (pouw-node#90). The peer is a store that holds a chain: it
// answers the requests of the node with `sync::answer`, as a node does.

/// The valid child of `parent`, `secs` after it, with the target of the rule.
fn child(parent: &Block, secs: u64) -> Block {
    let params = test_params();
    let anchor = Anchor::first_block(&params, &genesis_block().header);
    let target = next_target(&params, SystemId(0), &anchor, &parent.header).unwrap();
    raw_block(
        parent.header.height.get().saturating_add(1),
        block_id(&parent.header),
        parent.header.timestamp.get().saturating_add(secs),
        target,
        vec![],
    )
}

/// `count` blocks after `parent`, each `secs` after the one before. A block every ten
/// seconds is the pace of the rule, so the target stays where it is and mining stays cheap.
fn extend(parent: &Block, count: u64, secs: u64) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut tip = parent.clone();
    for _ in 0..count {
        tip = child(&tip, secs);
        blocks.push(tip.clone());
    }
    blocks
}

/// The store of a peer whose chain is `chain`, the genesis first.
fn their_store(chain: &[Block]) -> store::Store {
    let mut theirs = store::memory();
    for block in chain {
        let id = put(&mut theirs, block);
        store::connect_block(&mut theirs, &id, &[], &StateDiff::default()).unwrap();
    }
    theirs
}

/// The `Status` of the peer with the chain of `theirs`, on our chain id and genesis.
fn status_of_peer(h: &Harness, theirs: &store::Store) -> Status {
    let tip = store::tip(&store::read(theirs).unwrap()).unwrap().unwrap();
    Status {
        tip: tip.id,
        height: tip.height,
        cumulative_work: tip.cumulative_work,
        ..status_of(h)
    }
}

fn fetched(theirs: &store::Store, request: &SyncRequest) -> Fetched {
    match sync::answer(theirs, request).unwrap() {
        SyncResponse::Headers(headers) => Fetched::Headers(headers),
        SyncResponse::Blocks(blocks) => Fetched::Blocks(
            blocks
                .iter()
                .map(|bytes| checked(borsh::from_slice(bytes).unwrap()))
                .collect(),
        ),
    }
}

/// Runs the node and answers every request it sends to the peer from `theirs`, until it
/// asks nothing more, also after one tick. Returns the requests in the order they were
/// sent and what the node reported. Never more than one `GetBlocks` is out at a time.
fn sync_with(
    h: &mut Harness,
    theirs: &store::Store,
) -> (Vec<SyncRequest>, Vec<(PeerIx, Misbehavior)>) {
    let mut seen = Vec::new();
    let mut reported = Vec::new();
    let mut ticked = false;
    loop {
        run(h);
        let mut asked = Vec::new();
        for command in drain(h) {
            match command {
                Command::Request { id, request, .. } => asked.push((id, request)),
                Command::Report(peer, why) => reported.push((peer, why)),
                _ => {}
            }
        }
        if asked.is_empty() {
            if ticked {
                return (seen, reported);
            }
            ticked = true;
            node::on_tick(&mut h.state).unwrap();
            continue;
        }
        ticked = false;
        let windows = asked
            .iter()
            .filter(|(_, request)| matches!(request, SyncRequest::GetBlocks(_)))
            .count();
        assert!(windows <= 1, "{windows} windows in flight");
        for (id, request) in asked {
            let result = Ok(fetched(theirs, &request));
            seen.push(request);
            to_node(h, Inbound::Response { id, result });
        }
    }
}

fn same_blocks(h: &Harness, theirs: &store::Store, chain: &[Block]) {
    let ours = store::read(&h.state.store).unwrap();
    let theirs = store::read(theirs).unwrap();
    for block in chain {
        let id = block_id(&block.header);
        assert_eq!(
            store::header(&ours, &id).unwrap(),
            store::header(&theirs, &id).unwrap()
        );
        assert_eq!(
            store::block(&ours, &id).unwrap().map(|b| b.bytes.to_vec()),
            store::block(&theirs, &id)
                .unwrap()
                .map(|b| b.bytes.to_vec()),
        );
    }
}

#[test]
fn a_node_that_starts_empty_downloads_the_chain_of_its_peer() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let mut chain = vec![genesis.clone()];
    chain.extend(extend(&genesis, 5000, 10));
    let theirs = their_store(&chain);
    status_from_peer(&h, status_of_peer(&h, &theirs));
    let (requests, reported) = sync_with(&mut h, &theirs);
    assert_eq!(reported, Vec::new());
    assert_eq!(tip_height(&h), Some(Height(5000)));
    let tip = chain.last().unwrap();
    let ours = store::tip(&store::read(&h.state.store).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(ours.id, block_id(&tip.header));
    same_blocks(&h, &theirs, &chain);
    assert_eq!(h.state.metrics.dropped_blocks, 0);

    // three pages of headers (2000, 2000, 1000), the later ones from the last header
    let header_asks: Vec<&GetHeaders> = requests
        .iter()
        .filter_map(|request| match request {
            SyncRequest::GetHeaders(get) => Some(&**get),
            SyncRequest::GetBlocks(_) => None,
        })
        .collect();
    assert_eq!(header_asks.len(), 3);
    let first_of_page = |page: usize| block_id(&chain[page * 2000].header);
    assert_eq!(header_asks[1].locator[0], first_of_page(1));
    assert_eq!(header_asks[2].locator[0], first_of_page(2));
    assert!(header_asks.iter().all(|get| get.locator.len() <= 64));

    // every body once, in windows of at most 16
    let mut asked = Vec::new();
    for request in &requests {
        if let SyncRequest::GetBlocks(get) = request {
            assert!(get.ids.len() <= 16);
            asked.extend(get.ids.iter().copied());
        }
    }
    assert_eq!(asked.len(), 5000);
    assert_eq!(asked.iter().collect::<BTreeSet<_>>().len(), 5000);
    let heights: Vec<BlockId> = chain.iter().skip(1).map(|b| block_id(&b.header)).collect();
    assert_eq!(asked, heights);
}

#[test]
fn a_peer_on_a_fork_with_more_work_switches_the_chain() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let ours = extend(&genesis, 10, 10);
    for block in &ours {
        deliver(&mut h, block);
    }
    run(&mut h);
    assert_eq!(tip_height(&h), Some(Height(10)));
    assert_eq!(reports(&mut h), Vec::new());

    // the peer shares the first five blocks and goes on to 15 on its own
    let mut chain = vec![genesis.clone()];
    chain.extend(ours.iter().take(5).cloned());
    let fork_point = chain.last().unwrap().clone();
    chain.extend(extend(&fork_point, 10, 11));
    let theirs = their_store(&chain);
    status_from_peer(&h, status_of_peer(&h, &theirs));
    let (requests, reported) = sync_with(&mut h, &theirs);
    assert_eq!(reported, Vec::new());
    assert_eq!(tip_height(&h), Some(Height(15)));
    let tip = chain.last().unwrap();
    let now = store::tip(&store::read(&h.state.store).unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(now.id, block_id(&tip.header));
    same_blocks(&h, &theirs, &chain);

    // only the ten blocks of the fork were fetched, not the five we had
    let asked: usize = requests
        .iter()
        .map(|request| match request {
            SyncRequest::GetBlocks(get) => get.ids.len(),
            SyncRequest::GetHeaders(_) => 0,
        })
        .sum();
    assert_eq!(asked, 10);
}

#[test]
fn a_chain_below_min_chain_work_is_kept_as_headers_and_no_body_is_asked() {
    let mut h = harness();
    h.state.min_chain_work = CumWork(U256::MAX);
    let genesis = with_genesis(&mut h);
    let mut chain = vec![genesis.clone()];
    chain.extend(extend(&genesis, 30, 10));
    let theirs = their_store(&chain);
    status_from_peer(&h, status_of_peer(&h, &theirs));
    let (requests, reported) = sync_with(&mut h, &theirs);
    assert_eq!(reported, Vec::new());
    assert!(
        requests
            .iter()
            .all(|request| matches!(request, SyncRequest::GetHeaders(_)))
    );
    assert_eq!(tip_height(&h), Some(Height(0)));
    let reader = store::read(&h.state.store).unwrap();
    let last = block_id(&chain.last().unwrap().header);
    let entry = store::index(&reader, &last).unwrap().unwrap();
    assert_eq!(entry.height(), Height(30));
    assert!(store::block(&reader, &last).unwrap().is_none());
}

/// Blocks 1 and 2, a block 3 whose header does not meet its target, and nine more.
fn chain_with_a_bad_work_claim(genesis: &Block) -> Vec<Block> {
    let mut chain = vec![genesis.clone()];
    chain.extend(extend(genesis, 2, 10));
    let mut bad = child(chain.last().unwrap(), 10);
    while block_id(&bad.header).0.0 <= bad.header.target.0 {
        bad.header.nonce = U64::new(bad.header.nonce.get().wrapping_add(1));
    }
    chain.push(bad.clone());
    chain.extend(extend(&bad, 9, 10));
    chain
}

#[test]
fn the_ancestors_of_assume_valid_skip_the_work_check_and_the_other_blocks_do_not() {
    // with assume_valid at block 10 the bad claim of block 3 is not looked at
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let chain = chain_with_a_bad_work_claim(&genesis);
    let theirs = their_store(&chain);
    h.state.assume_valid = chain.get(10).map(|block| block_id(&block.header));
    status_from_peer(&h, status_of_peer(&h, &theirs));
    let (_, reported) = sync_with(&mut h, &theirs);
    assert_eq!(reported, Vec::new());
    assert_eq!(tip_height(&h), Some(Height(12)));

    // without it the claim is checked, the peer is reported, and the blocks it sent
    // after the bad one are dropped, not stored
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let chain = chain_with_a_bad_work_claim(&genesis);
    let theirs = their_store(&chain);
    status_from_peer(&h, status_of_peer(&h, &theirs));
    let (_, reported) = sync_with(&mut h, &theirs);
    assert_eq!(reported, [(peer(), Misbehavior::InvalidBlock)]);
    assert_eq!(tip_height(&h), Some(Height(2)));
    let reader = store::read(&h.state.store).unwrap();
    let fourth = block_id(&chain[4].header);
    assert!(store::block(&reader, &fourth).unwrap().is_none());
}

#[test]
fn headers_that_do_not_link_are_reported_and_no_body_is_asked() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let blocks = extend(&genesis, 3, 10);
    let id = pend(
        &mut h,
        SyncRequest::GetHeaders(Box::new(GetHeaders {
            locator: vec![block_id(&genesis.header)],
            stop: None,
        })),
    );
    // the second header does not have the first as its parent
    let headers = vec![blocks[0].header, blocks[2].header];
    let result = Ok(Fetched::Headers(headers));
    to_node(&h, Inbound::Response { id, result });
    run(&mut h);
    let commands = drain(&mut h);
    assert!(
        matches!(
            commands.as_slice(),
            [Command::Report(who, Misbehavior::InvalidBlock)] if *who == peer()
        ),
        "{commands:?}"
    );
}

#[test]
fn headers_of_a_peer_that_ignored_our_locator_are_reported() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let blocks = extend(&genesis, 3, 10);
    let id = pend(
        &mut h,
        SyncRequest::GetHeaders(Box::new(GetHeaders {
            locator: vec![block_id(&genesis.header)],
            stop: None,
        })),
    );
    // the answer starts above a block we do not have
    let result = Ok(Fetched::Headers(vec![blocks[1].header]));
    to_node(&h, Inbound::Response { id, result });
    run(&mut h);
    assert_eq!(reports(&mut h), [(peer(), Misbehavior::InvalidBlock)]);
}

// Two nodes, each with its own transport thread and libp2p swarm on 127.0.0.1
// (pouw-node#86): what one node pools and broadcasts, the other pools.

/// A port nothing listens on at the moment.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Starts the transport of `h` on its own thread, listening on `port` and dialing
/// `bootnodes`, and returns the directory of its key. The transport takes the commands
/// of the node from now on.
fn start_transport(
    h: &mut Harness,
    name: &str,
    port: u16,
    bootnodes: Vec<String>,
) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pouw-two-nodes-{}-{name}", std::process::id()));
    drop(std::fs::remove_dir_all(&dir));
    let config = crate::p2p::TransportConfig {
        network: pouw_types::NetworkName::try_from("devnet".to_owned()).unwrap(),
        listen: vec![format!("/ip4/127.0.0.1/tcp/{port}")],
        bootnodes,
        limits: crate::p2p::PeerLimits::default(),
        data_dir: dir.clone(),
    };
    let (_, unused) = mpsc::channel(1);
    let outbound = std::mem::replace(&mut h.outbound, unused);
    let inbound = h.feeds.p2p.clone();
    std::thread::spawn(move || {
        drop(crate::p2p::run_transport(
            &config,
            &test_params(),
            outbound,
            &inbound,
        ));
    });
    dir
}

#[test]
fn a_transaction_submitted_to_one_node_reaches_the_mempool_of_another() {
    let mut a = harness();
    let mut b = harness();
    with_genesis(&mut a);
    with_genesis(&mut b);
    let port = free_port();
    let dir_a = start_transport(&mut a, "a", port, vec![]);
    let dir_b = start_transport(
        &mut b,
        "b",
        free_port(),
        vec![format!("/ip4/127.0.0.1/tcp/{port}")],
    );

    // The peers learn each other's topics a moment after they connect, and a message
    // published before that reaches nobody. So a new transaction goes to the first node
    // every half second (each from a sender of its own, so none is refused as a
    // duplicate or for lack of slots) until the second node has one.
    let start = std::time::Instant::now();
    let mut sent = Vec::new();
    let mut replies = Vec::new();
    let mut seed = 0u8;
    let mut last = None::<std::time::Instant>;
    while b.state.mempool.txs.is_empty() {
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "no transaction reached the second node, {} were sent",
            sent.len()
        );
        if last.is_none_or(|at| at.elapsed() >= Duration::from_millis(500)) {
            let tx = transfer_from(seed, CHAIN, 0);
            seed = seed.wrapping_add(1);
            let (reply, answer) = oneshot::channel();
            let checked = submitted(tx.clone());
            to_api(&a, ApiRequest::SubmitTx { checked, reply });
            sent.push(tx);
            replies.push(answer);
            last = Some(std::time::Instant::now());
        }
        run(&mut a);
        run(&mut b);
        std::thread::sleep(Duration::from_millis(20));
    }
    let arrived = sent
        .iter()
        .filter(|tx| mempool::get(&b.state.mempool, &txid(tx)).is_some())
        .count();
    assert!(
        arrived >= 1,
        "the pool of the second node holds no sent transaction"
    );
    // the first node keeps what it was sent
    assert!(a.state.mempool.txs.len() >= arrived);
    assert_eq!(a.state.metrics.dropped_commands, 0);
    assert_eq!(b.state.metrics.dropped_commands, 0);
    drop(std::fs::remove_dir_all(dir_a));
    drop(std::fs::remove_dir_all(dir_b));
}

// Network metrics (pouw-node#87).

use crate::metrics::MessageKind;

#[test]
fn messages_are_counted_by_kind_when_they_come_and_when_they_go() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let child = block(&genesis, vec![]);
    gossip(&mut h, Gossip::Tx(Box::new(checked_tx(transfer(CHAIN, 0)))));
    announce(&mut h, child.header);
    status_from_peer(&h, status_of(&h));
    to_node(
        &h,
        Inbound::Request {
            from: peer(),
            serve: ServeId(0),
            request: SyncRequest::GetBlocks(GetBlocks { ids: vec![] }),
        },
    );
    deliver(&mut h, &child);
    run(&mut h);

    let metrics = &h.state.metrics;
    for (kind, want) in [
        (MessageKind::CoinTx, 1),
        (MessageKind::BlockAnnounce, 1),
        (MessageKind::ProofRequest, 0),
        (MessageKind::Status, 1),
        (MessageKind::SyncRequest, 1),
        (MessageKind::SyncResponse, 1),
    ] {
        assert_eq!(metrics.received_of(kind), want, "{kind:?}");
    }

    // what went out is what the commands say: a request for the announced block and the
    // answer to the request of the peer
    let commands = drain(&mut h);
    let count = |pick: fn(&Command) -> bool| {
        u64::try_from(commands.iter().filter(|command| pick(command)).count()).unwrap()
    };
    let requests = count(|command| matches!(command, Command::Request { .. }));
    let answers = count(|command| matches!(command, Command::Answer { .. }));
    assert!(requests >= 1 && answers == 1, "{commands:?}");
    assert_eq!(h.state.metrics.sent_of(MessageKind::SyncRequest), requests);
    assert_eq!(h.state.metrics.sent_of(MessageKind::SyncResponse), answers);
}

#[test]
fn a_status_and_a_broadcast_of_the_node_are_counted_when_it_sends_them() {
    let mut h = harness();
    with_genesis(&mut h);
    to_node(
        &h,
        Inbound::PeerConnected {
            peer: peer(),
            peer_id: "70".into(),
        },
    );
    let (reply, mut answer) = oneshot::channel();
    let checked = submitted(transfer(CHAIN, 0));
    to_api(&h, ApiRequest::SubmitTx { checked, reply });
    run(&mut h);
    assert!(matches!(answer.try_recv(), Ok(TxOutcome::Pooled(_))));
    let metrics = &h.state.metrics;
    assert_eq!(metrics.peers, 1);
    for (kind, want) in [
        (MessageKind::Status, 1),
        (MessageKind::CoinTx, 1),
        (MessageKind::BlockAnnounce, 0),
        (MessageKind::ProofRequest, 0),
        (MessageKind::SyncRequest, 0),
        (MessageKind::SyncResponse, 0),
    ] {
        assert_eq!(metrics.sent_of(kind), want, "{kind:?}");
    }
}

#[test]
fn a_command_the_full_channel_dropped_is_not_counted_as_sent() {
    let mut h = harness();
    with_genesis(&mut h);
    let capacity = node::COMMAND_CAPACITY;
    let filled = u64::try_from(capacity).unwrap();
    for _ in 0..capacity {
        let status = Box::new(node::our_status(&h.state).unwrap());
        let command = Command::Status {
            peer: peer(),
            status,
        };
        crate::p2p::send(&h.state.network, command, &mut h.state.metrics).unwrap();
    }
    assert_eq!(h.state.metrics.sent_of(MessageKind::Status), filled);
    let status = Box::new(node::our_status(&h.state).unwrap());
    let command = Command::Status {
        peer: peer(),
        status,
    };
    crate::p2p::send(&h.state.network, command, &mut h.state.metrics).unwrap();
    assert_eq!(h.state.metrics.sent_of(MessageKind::Status), filled);
    assert_eq!(h.state.metrics.dropped_commands, 1);
}

#[test]
fn the_delay_of_an_announced_block_is_its_age_when_the_announcement_arrives() {
    let mut h = harness();
    let genesis = with_genesis(&mut h);
    let child = block(&genesis, vec![]);
    set_clock(child.header.timestamp.get().saturating_add(7));
    announce(&mut h, child.header);
    // the same announcement again is known and not counted
    announce(&mut h, child.header);
    run(&mut h);
    assert_eq!(
        (
            h.state.metrics.block_delays,
            h.state.metrics.block_delay_secs
        ),
        (1, 7)
    );
}
