//! The node API of `contracts/node-api.md` in Rust: the JSON views, the error body,
//! the event types of `contracts/node-events.md`, the endpoint paths and a client.
//! The node serves these types and every Rust consumer reads them, so a shape changes
//! in one place.
//!
//! [`NodeClient`] has the method of every endpoint. It has no HTTP transport yet: every
//! method answers [`ClientError::NoTransport`].

#![forbid(unsafe_code)]

pub mod error;
pub mod event;
pub mod path;
pub mod view;

use pouw_crypto::Address;
use pouw_types::{CircuitId, Height, SignedTx, TxId};
use thiserror::Error;

use crate::{
    error::ErrorBody,
    event::EventsPage,
    view::{
        AccountView, BlockView, BlocksPage, CircuitView, HeaderView, HeadersPage, InclusionProof,
        MempoolView, NodeInfo, TxView,
    },
};

/// Why a call to the node failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error("the client has no HTTP transport")]
    NoTransport,
    /// The request did not reach the node or the answer did not arrive.
    #[error("transport failure: {0}")]
    Transport(#[source] std::io::Error),
    /// The node answered with an error body.
    #[error("node answered {status} {}: {}", body.error.code, body.error.message)]
    Api {
        /// HTTP status.
        status: u16,
        /// The error body.
        body: ErrorBody,
    },
    #[error("cannot decode the answer: {0}")]
    Decode(#[source] serde_json::Error),
}

/// Handle to one node, addressed by the base URL of its REST API.
#[derive(Debug, Clone)]
pub struct NodeClient {
    base_url: String,
}

#[expect(
    clippy::unused_async,
    clippy::unused_async_trait_impl,
    reason = "the methods have the signatures of the HTTP client"
)]
impl NodeClient {
    /// A client of the node at `base_url`, such as `http://node-1:8000`.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
        }
    }

    /// The base URL given to [`NodeClient::new`].
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// `POST /v1/txs` with the borsh bytes of `tx`.
    pub async fn submit_tx(&self, _tx: &SignedTx) -> Result<TxId, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/txs/{txid}`
    pub async fn tx(&self, _id: &TxId) -> Result<TxView, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/txs/{txid}/inclusion-proof`
    pub async fn inclusion_proof(&self, _id: &TxId) -> Result<InclusionProof, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/blocks/head`
    pub async fn head(&self) -> Result<HeaderView, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/blocks/{height}`
    pub async fn block(&self, _height: Height) -> Result<BlockView, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/blocks/{height}/header`
    pub async fn header(&self, _height: Height) -> Result<HeaderView, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/blocks?from=&to=`, at most [`view::MAX_BLOCKS_PER_CALL`] blocks.
    pub async fn blocks(&self, _from: Height, _to: Height) -> Result<BlocksPage, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/headers?from=&to=`, at most [`view::MAX_HEADERS_PER_CALL`] headers.
    pub async fn headers(&self, _from: Height, _to: Height) -> Result<HeadersPage, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/circuits`
    pub async fn circuits(&self) -> Result<Vec<CircuitView>, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/circuits/{circuit_id}`, with `?include=keys` when `include_keys`.
    pub async fn circuit(
        &self,
        _id: &CircuitId,
        _include_keys: bool,
    ) -> Result<CircuitView, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/accounts/{addr}`
    pub async fn account(&self, _address: &Address) -> Result<AccountView, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/mempool`
    pub async fn mempool(&self) -> Result<MempoolView, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/events?after=&limit=&wait_ms=`
    pub async fn events(
        &self,
        _after: u64,
        _limit: u32,
        _wait_ms: u64,
    ) -> Result<EventsPage, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /v1/node`
    pub async fn node_info(&self) -> Result<NodeInfo, ClientError> {
        Err(ClientError::NoTransport)
    }

    /// `GET /health`
    pub async fn health(&self) -> Result<(), ClientError> {
        Err(ClientError::NoTransport)
    }
}

#[cfg(test)]
mod tests;
