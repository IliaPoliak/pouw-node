//! The `pouw-light-node` binary: reads the configuration from the environment and
//! serves `/health` and the header routes of the light API until SIGINT or SIGTERM. `RUST_LOG` filters the log, `info` by
//! default.
//!
//! Exit codes: 0 after a shutdown signal, 1 when the light node cannot start, 2 for an
//! invalid configuration.

use std::{
    env, fs,
    net::TcpListener,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use pouw_light_node::{
    api::{self, LightApi},
    config::LightConfig,
    headers::HeaderStore,
    sync::{HeaderSync, load_chain},
    upstream::Upstream,
};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

fn main() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let vars = env::vars_os().map(|(name, value)| {
        (
            name.to_string_lossy().into_owned(),
            value.to_string_lossy().into_owned(),
        )
    });
    let config = match LightConfig::from_vars(vars) {
        Ok(config) => config,
        Err(error) => {
            error!(%error, "invalid configuration");
            return ExitCode::from(2);
        }
    };
    let mut signals = match Signals::new([SIGINT, SIGTERM]) {
        Ok(signals) => signals,
        Err(error) => {
            error!(%error, "cannot register the signal handlers");
            return ExitCode::FAILURE;
        }
    };
    let listener = match TcpListener::bind(config.api_addr) {
        Ok(listener) => listener,
        Err(error) => {
            error!(%error, addr = %config.api_addr, "cannot bind the API address");
            return ExitCode::FAILURE;
        }
    };
    if let Err(error) = fs::create_dir_all(&config.data_dir) {
        error!(%error, dir = %config.data_dir.display(), "cannot create the data directory");
        return ExitCode::FAILURE;
    }
    let mut headers =
        match HeaderStore::open(&config.data_dir.join("headers.bin"), config.header_cache) {
            Ok(headers) => headers,
            Err(error) => {
                error!(%error, "cannot open the header store");
                return ExitCode::FAILURE;
            }
        };
    if let Some((height, id)) = headers.tip() {
        info!(
            height = height.0,
            %id,
            stored = headers.len(),
            "continuing from the last stored header"
        );
    } else {
        info!("the header store is empty");
    }
    if config.full_nodes.is_empty() {
        warn!("no full node configured, set POUW_FULL_NODES");
    }
    info!(
        addr = %config.api_addr,
        full_nodes = config.full_nodes.len(),
        "light node started"
    );
    let upstream = Upstream::new(&config.full_nodes);
    if upstream.len() < config.full_nodes.len() {
        warn!("only http:// full nodes are used, the others are left out");
    }
    let syncer = match start_sync(&config, &upstream, &mut headers) {
        Ok(syncer) => syncer,
        Err(code) => return code,
    };
    let api = Arc::new(LightApi::new(headers, upstream));
    let stop = Arc::new(AtomicBool::new(false));
    let followed = Arc::clone(&api);
    let halt = Arc::clone(&stop);
    let follower = thread::Builder::new()
        .name("sync".to_owned())
        .spawn(move || syncer.run(followed.store(), &halt));
    if let Err(error) = follower {
        error!(%error, "cannot start the sync thread");
        return ExitCode::FAILURE;
    }
    let server = thread::Builder::new()
        .name("api".to_owned())
        .spawn(move || api::serve(&listener, &api));
    if let Err(error) = server {
        error!(%error, "cannot start the API thread");
        return ExitCode::FAILURE;
    }
    if let Some(signal) = signals.forever().next() {
        info!(signal, "shutdown requested");
    }
    stop.store(true, Ordering::Relaxed);
    ExitCode::SUCCESS
}

/// The sync of the chain of the chain spec, started on the header store. The error is
/// the exit code of the process.
fn start_sync(
    config: &LightConfig,
    upstream: &Upstream,
    headers: &mut HeaderStore,
) -> Result<HeaderSync, ExitCode> {
    let (spec, genesis) = match load_chain(config.chain_spec.as_deref()) {
        Ok(chain) => chain,
        Err(error) => {
            error!(%error, "invalid chain spec");
            return Err(ExitCode::from(2));
        }
    };
    info!(
        network = %spec.network,
        genesis = %spec.expected_genesis_id,
        "following the chain of the chain spec"
    );
    let syncer = HeaderSync::new(spec.params, genesis, upstream.clone());
    if let Err(error) = syncer.start(headers) {
        error!(%error, "the stored headers are not of the chain of the chain spec");
        return Err(ExitCode::FAILURE);
    }
    Ok(syncer)
}
