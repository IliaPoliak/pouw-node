//! The `pouw-light-node` binary: reads the configuration from the environment and
//! serves `/health` until SIGINT or SIGTERM. `RUST_LOG` filters the log, `info` by
//! default.
//!
//! Exit codes: 0 after a shutdown signal, 1 when the light node cannot start, 2 for an
//! invalid configuration.

use std::{env, net::TcpListener, process::ExitCode, thread};

use pouw_light_node::{config::LightConfig, health};
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
    if config.full_nodes.is_empty() {
        warn!("no full node configured, set POUW_FULL_NODES");
    }
    info!(
        addr = %config.api_addr,
        full_nodes = config.full_nodes.len(),
        "light node started"
    );
    let server = thread::Builder::new()
        .name("health".to_owned())
        .spawn(move || health::serve(&listener));
    if let Err(error) = server {
        error!(%error, "cannot start the health thread");
        return ExitCode::FAILURE;
    }
    if let Some(signal) = signals.forever().next() {
        info!(signal, "shutdown requested");
    }
    ExitCode::SUCCESS
}
