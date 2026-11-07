//! Light node configuration from `POUW_*` environment variables, with the same rules as
//! the full node: every variable has a default and an unknown `POUW_*` variable is an
//! error, so a typo does not go unnoticed.

use std::{
    net::{AddrParseError, SocketAddr},
    num::ParseIntError,
    path::PathBuf,
};

use thiserror::Error;

/// Variable names and their defaults.
pub mod var {
    /// Address of `/health` and the light API. Default `[::]:8000`, both IP families.
    pub const API_ADDR: &str = "POUW_LIGHT_API_ADDR";
    /// Comma-separated base URLs of the full nodes to read from, such as
    /// `http://node-1:8000`. Default empty: the light node starts and has nothing to
    /// follow.
    pub const FULL_NODES: &str = "POUW_FULL_NODES";
    /// Directory of the header file. Default `data`.
    pub const DATA_DIR: &str = "POUW_LIGHT_DATA_DIR";
    /// Most recent headers kept in memory, at least 1. Default `1024`.
    pub const HEADER_CACHE: &str = "POUW_LIGHT_HEADER_CACHE";
}

const KNOWN: [&str; 4] = [
    var::API_ADDR,
    var::FULL_NODES,
    var::DATA_DIR,
    var::HEADER_CACHE,
];

const DEFAULT_HEADER_CACHE: usize = 1024;

const DEFAULT_API_ADDR: &str = "[::]:8000";

/// What is wrong with the value of a variable.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Reason {
    #[error("not a positive number: {0}")]
    Count(String),
    #[error("not a number: {0}")]
    Number(#[from] ParseIntError),
    #[error("not a socket address: {0}")]
    Socket(#[from] AddrParseError),
    #[error("not a base url like http://host:port: {0:?}")]
    Url(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// A variable has a value the light node cannot use.
    #[error("{var}={value:?}: {reason}")]
    Invalid {
        var: &'static str,
        value: String,
        #[source]
        reason: Reason,
    },
    /// A `POUW_*` variable the light node does not read.
    #[error("unknown variable {0}")]
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LightConfig {
    /// Where `/health` is served.
    pub api_addr: SocketAddr,
    /// Base URLs of the full nodes, without a trailing slash.
    pub full_nodes: Vec<String>,
    /// Directory of the header file.
    pub data_dir: PathBuf,
    /// Most recent headers kept in memory.
    pub header_cache: usize,
}

impl LightConfig {
    /// Reads the configuration from `vars`, the pairs of the environment. Variables that
    /// do not start with `POUW_` are ignored.
    ///
    /// # Errors
    ///
    /// [`ConfigError::Unknown`] for a `POUW_*` variable that is not in [`var`],
    /// [`ConfigError::Invalid`] for a value that does not parse.
    pub fn from_vars<I>(vars: I) -> Result<Self, ConfigError>
    where
        I: IntoIterator<Item = (String, String)>,
    {
        let mut api_addr = None;
        let mut full_nodes = None;
        let mut data_dir = None;
        let mut header_cache = None;
        for (name, value) in vars {
            match name.as_str() {
                var::API_ADDR => api_addr = Some(value),
                var::FULL_NODES => full_nodes = Some(value),
                var::DATA_DIR => data_dir = Some(value),
                var::HEADER_CACHE => header_cache = Some(value),
                other if other.starts_with("POUW_") && !KNOWN.contains(&other) => {
                    return Err(ConfigError::Unknown(name));
                }
                _ => {}
            }
        }
        let api_text = api_addr.unwrap_or_else(|| DEFAULT_API_ADDR.to_owned());
        let api_addr = api_text
            .parse::<SocketAddr>()
            .map_err(|error| ConfigError::Invalid {
                var: var::API_ADDR,
                value: api_text.clone(),
                reason: error.into(),
            })?;
        let nodes_text = full_nodes.unwrap_or_default();
        let full_nodes = parse_full_nodes(&nodes_text).map_err(|reason| ConfigError::Invalid {
            var: var::FULL_NODES,
            value: nodes_text.clone(),
            reason,
        })?;
        let header_cache = match header_cache {
            None => DEFAULT_HEADER_CACHE,
            Some(text) => text
                .parse::<usize>()
                .map_err(Reason::from)
                .and_then(|count| {
                    if count == 0 {
                        Err(Reason::Count(text.clone()))
                    } else {
                        Ok(count)
                    }
                })
                .map_err(|reason| ConfigError::Invalid {
                    var: var::HEADER_CACHE,
                    value: text.clone(),
                    reason,
                })?,
        };
        Ok(Self {
            api_addr,
            full_nodes,
            data_dir: PathBuf::from(data_dir.unwrap_or_else(|| "data".to_owned())),
            header_cache,
        })
    }
}

fn parse_full_nodes(text: &str) -> Result<Vec<String>, Reason> {
    let mut nodes = Vec::new();
    for item in text
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        let host = item
            .strip_prefix("http://")
            .or_else(|| item.strip_prefix("https://"))
            .ok_or_else(|| Reason::Url(item.to_owned()))?;
        let host = host.strip_suffix('/').unwrap_or(host);
        if host.is_empty() || host.contains(|c: char| c == '/' || c.is_whitespace()) {
            return Err(Reason::Url(item.to_owned()));
        }
        nodes.push(item.strip_suffix('/').unwrap_or(item).to_owned());
    }
    Ok(nodes)
}

#[cfg(test)]
mod tests;
