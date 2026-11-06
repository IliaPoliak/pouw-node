//! The `pouw-node` binary: reads the configuration from the environment, opens the
//! store, starts every component on its own thread and runs the node loop on the main
//! thread until SIGINT or SIGTERM. `RUST_LOG` filters the log, `info` by default.
//!
//! Exit codes: 0 after a shutdown signal, 1 when the node cannot start, 2 for an invalid
//! configuration or `RUST_LOG`, 3 when the loop stopped on a fault.

use std::{
    collections::VecDeque,
    env::{self, VarError},
    io,
    process::ExitCode,
    thread,
};

use pouw_api::event::{EVENT_RETENTION, EventKind, NodeStarted};
use pouw_node::{
    api,
    chain::{self, GenesisError},
    config::{NodeConfig, ProverKind, load_chain},
    events::{self, EventLog, SeqExhausted},
    mempool,
    metrics::{self, Metrics},
    miner,
    node::{
        self, COMMAND_CAPACITY, Component, ComponentFault, Control, Feeds, JOBS_CAPACITY,
        NodeFault, NodeState,
    },
    p2p::{self, RequestId, TransportConfig, protocol::Services},
    signals,
    store::{self, StoreError},
};
#[cfg(feature = "groth16")]
use pouw_provers::Groth16;
use pouw_provers::{MockProver, ProofSystem, Prover};
use pouw_types::{Block, ChainSpec};
use signal_hook::iterator::Signals;
use thiserror::Error;
use tokio::sync::mpsc;
use tracing::{error, info};
use tracing_subscriber::{EnvFilter, filter::ParseError};

#[derive(Debug, Error)]
enum StartError {
    #[error("pouw-node#93: the Groth16 prover needs the `groth16` feature, which is off")]
    NoGroth16,
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Genesis(#[from] GenesisError),
    #[error("cannot start a thread: {0}")]
    Thread(#[source] io::Error),
    #[error("cannot register the signal handlers: {0}")]
    Signals(#[source] io::Error),
    #[error(transparent)]
    EventSeq(#[from] SeqExhausted),
    #[error("the node loop stopped on a fault: {0}")]
    Fault(#[from] NodeFault),
}

#[derive(Debug, Error)]
enum LogFilterError {
    #[error("RUST_LOG is not unicode")]
    NotUnicode,
    #[error("RUST_LOG is not a filter: {0}")]
    Invalid(#[from] ParseError),
}

fn log_filter() -> Result<EnvFilter, LogFilterError> {
    match env::var(EnvFilter::DEFAULT_ENV) {
        Ok(directives) => Ok(EnvFilter::try_new(directives)?),
        Err(VarError::NotPresent) => Ok(EnvFilter::new("info")),
        Err(VarError::NotUnicode(_)) => Err(LogFilterError::NotUnicode),
    }
}

fn main() -> ExitCode {
    let (filter, bad_filter) = match log_filter() {
        Ok(filter) => (filter, None),
        Err(error) => (EnvFilter::new("info"), Some(error)),
    };
    tracing_subscriber::fmt().with_env_filter(filter).init();
    if let Some(error) = bad_filter {
        error!(%error, "invalid log filter");
        return ExitCode::from(2);
    }
    let config = match NodeConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            error!(%error, "invalid configuration");
            return ExitCode::from(2);
        }
    };
    info!(?config, "configuration loaded");
    let (spec, genesis) = match load_chain(config.chain_spec.as_deref()) {
        Ok(loaded) => loaded,
        Err(error) => {
            error!(%error, "invalid chain spec");
            return ExitCode::from(2);
        }
    };
    info!(
        network = %spec.network,
        chain_id = spec.params.chain_id.0,
        genesis = %spec.expected_genesis_id,
        "chain spec loaded"
    );
    match start(config, &spec, &genesis) {
        Ok(()) => {
            info!("node stopped on request");
            ExitCode::SUCCESS
        }
        Err(StartError::Fault(fault)) => {
            error!(%fault, "node stopped on a fault");
            ExitCode::from(3)
        }
        Err(error) => {
            error!(%error, "cannot start the node");
            ExitCode::FAILURE
        }
    }
}

fn start(config: NodeConfig, spec: &ChainSpec, genesis: &Block) -> Result<(), StartError> {
    let prover = match config.prover {
        ProverKind::Mock { delay } => Prover::Mock(MockProver::new(ProofSystem::Groth16, delay)),
        #[cfg(feature = "groth16")]
        ProverKind::Groth16 => Prover::Groth16(Groth16),
        #[allow(unreachable_patterns, reason = "built in with the groth16 feature")]
        ProverKind::Groth16 => return Err(StartError::NoGroth16),
    };
    let mut store = store::open(config.store, &config.data_dir)?;
    let tip = chain::genesis(&mut store, spec, genesis)?;
    info!(?tip, "store opened");

    let (network, outbound) = mpsc::channel(COMMAND_CAPACITY);
    let (prover_jobs, jobs) = mpsc::channel(JOBS_CAPACITY);
    let (feeds, mut inbox) = node::channels();
    let mut state = NodeState {
        params: spec.params.clone(),
        min_chain_work: spec.min_chain_work,
        assume_valid: spec.assume_valid,
        services: Services::ARCHIVE,
        miner: config.miner,
        store,
        mempool: mempool::new(config.mempool),
        events: EventLog {
            node_id: config.node_id.clone(),
            retention: usize::try_from(EVENT_RETENTION).unwrap_or(usize::MAX),
            events: VecDeque::new(),
            last_seq: 0,
        },
        metrics: Metrics::default(),
        network,
        pending: Vec::new(),
        next_request: RequestId(0),
        work: miner::new_work(prover_jobs),
        clock: node::system_clock,
        ticks: 0,
    };
    info!(limits = ?config.mempool, "mempool ready");
    let started = NodeStarted {
        chain_id: spec.params.chain_id,
        version: env!("CARGO_PKG_VERSION").to_owned(),
        height: tip.height,
    };
    events::emit(&mut state.events, EventKind::NodeStarted(started))?;
    info!("event log started");

    let shutdown = Signals::new(signals::SHUTDOWN_SIGNALS).map_err(StartError::Signals)?;
    let transport = TransportConfig {
        network: spec.network.clone(),
        listen: config.p2p_listen,
        bootnodes: config.bootnodes,
        limits: config.limits,
    };
    let params = spec.params.clone();
    let worker_params = spec.params.clone();
    let Feeds {
        control,
        work,
        p2p: inbound,
        api: requests,
    } = feeds;
    let metrics_requests = requests.clone();
    let signal_control = control.clone();
    spawn(Component::P2p, &control, move || {
        p2p::run_transport(&transport, &params, outbound, &inbound)
    })?;
    spawn(Component::Api, &control, move || {
        api::serve(config.api_addr, config.api_fixtures.as_deref(), &requests)
    })?;
    spawn(Component::Metrics, &control, move || {
        metrics::serve(config.metrics_addr, &metrics_requests)
    })?;
    spawn(Component::Prover, &control, move || {
        miner::run_work_worker(&prover, &worker_params, jobs, &work)
    })?;
    spawn(Component::Signals, &control, move || {
        signals::run(shutdown, &signal_control)
    })?;
    if let Some(miner) = config.miner {
        info!(?miner, "block production on");
    } else {
        info!("block production off, no miner address");
    }
    info!("chain sync asks a peer whose status shows more work");

    drop(control);
    info!("node loop running");
    node::run(&mut state, &mut inbox)?;
    Ok(())
}

/// Runs `body` on a thread named after `component`. The thread is detached: its last
/// act is a [`Control::Stopped`] with the result of `body`, which reaches the loop
/// whatever way the thread ended (a panic aborts the process, see the profiles), so a
/// join handle would add nothing.
fn spawn<F>(
    component: Component,
    control: &mpsc::Sender<Control>,
    body: F,
) -> Result<(), StartError>
where
    F: FnOnce() -> Result<(), ComponentFault> + Send + 'static,
{
    let control = control.clone();
    thread::Builder::new()
        .name(format!("{component:?}"))
        .spawn(move || {
            let result = body();
            node::stopped(&control, component, result);
        })
        .map(drop)
        .map_err(StartError::Thread)
}
