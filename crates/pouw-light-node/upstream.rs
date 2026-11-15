//! The client the light node uses to ask a full node (`POUW_FULL_NODES`) for what it does
//! not hold itself: blocks, accounts, transactions, inclusion proofs.
//!
//! Plain HTTP/1.0 over a TCP stream, one request per connection, so the answer is never
//! chunked and ends when the connection closes. Only `http://` full nodes are used. The
//! nodes are tried in the order of the configuration; a node that cannot be reached or
//! answers 5xx is skipped, any other answer (also 404) is the answer.

use std::{
    io::{self, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    time::Duration,
};

use thiserror::Error;

const TIMEOUT: Duration = Duration::from_secs(5);
/// Most bytes of an answer that are read.
const MAX_ANSWER: u64 = 16 * 1024 * 1024;

/// What a full node answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub status: u16,
    pub content_type: String,
    pub body: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("no full node is configured")]
    NoNodes,
    #[error("no full node answered: {0}")]
    Unreachable(String),
}

/// The full nodes of the configuration, as `host:port`.
#[derive(Debug, Clone, Default)]
pub struct Upstream {
    nodes: Vec<String>,
}

impl Upstream {
    /// The `http://` entries of `urls`; others are left out (see [`Upstream::len`]).
    pub fn new(urls: &[String]) -> Self {
        let nodes = urls
            .iter()
            .filter_map(|url| url.strip_prefix("http://"))
            .map(|host| {
                if host.contains(':') {
                    host.to_owned()
                } else {
                    format!("{host}:80")
                }
            })
            .collect();
        Self { nodes }
    }

    /// How many full nodes are used.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// `GET path` on the first full node that answers below 500. `json` sets `Accept` to
    /// JSON, otherwise it asks for borsh.
    pub fn get(&self, path: &str, json: bool) -> Result<Answer, UpstreamError> {
        if self.nodes.is_empty() {
            return Err(UpstreamError::NoNodes);
        }
        let mut last = String::new();
        for node in &self.nodes {
            match fetch(node, path, json) {
                Ok(answer) if answer.status < 500 => return Ok(answer),
                Ok(answer) => last = format!("{node} answered {}", answer.status),
                Err(error) => last = format!("{node}: {error}"),
            }
        }
        Err(UpstreamError::Unreachable(last))
    }
}

fn fetch(node: &str, path: &str, json: bool) -> io::Result<Answer> {
    let addr = node
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::other("the host has no address"))?;
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let accept = if json {
        "application/json"
    } else {
        "application/octet-stream"
    };
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nhost: {node}\r\naccept: {accept}\r\nconnection: close\r\n\r\n"
    )?;
    let mut raw = Vec::new();
    (&stream).take(MAX_ANSWER).read_to_end(&mut raw)?;
    parse(&raw)
}

fn parse(raw: &[u8]) -> io::Result<Answer> {
    let bad = || io::Error::other("not an HTTP answer");
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(bad)?;
    let head = std::str::from_utf8(raw.get(..split).ok_or_else(bad)?).map_err(io::Error::other)?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(bad)?;
    let content_type = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-type"))
        .map_or_default(|(_, value)| value.trim().to_owned());
    let body = raw.get(split.saturating_add(4)..).ok_or_else(bad)?.to_vec();
    Ok(Answer {
        status,
        content_type,
        body,
    })
}

#[cfg(test)]
pub(crate) mod tests;
