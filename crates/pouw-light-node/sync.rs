//! The header sync of the light node (pouw-node#104): it follows the chain through the
//! full nodes of `POUW_FULL_NODES` and keeps the verified headers in the header store.
//!
//! One round ([`HeaderSync::step`]) asks each full node for its head (`/v1/blocks/head`)
//! and then:
//!
//! - the head is a header the store holds already: the node is not ahead, nothing to do;
//! - the head is above our tip on our chain: the missing headers are read in ranges of at
//!   most 1000 (`/v1/headers?from=&to=`) and each one is checked by [`crate::verify`]
//!   before it is stored;
//! - the head is on another branch: the common ancestor is found by probing single
//!   headers (steps that double, then a binary search), and the branch of the full node
//!   replaces ours only when it holds more work. The headers of the branch get their
//!   proof of work checked before anything is removed. The headers of ours that are
//!   removed are kept in memory, and put back if a header of the branch fails the checks.
//!
//! A full node that cannot be reached, answers something unusable or sends a chain that
//! does not verify is left for the next one of the list. The headers that verified up to
//! that point stay in the store.
//!
//! The chain starts at the genesis block of the chain spec (`POUW_CHAIN_SPEC`, the devnet
//! spec of the repository when unset). The store of another genesis is refused. A fork
//! deeper than [`MAX_REORG`] headers is refused too, and the branch of a fork is read up
//! to that many headers at a time.

use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::{
        PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use pouw_api::{
    path::{HEAD, HEADERS},
    view::{HeaderView, HeadersPage, MAX_HEADERS_PER_CALL},
};
use pouw_consensus::{ConsensusParams, check_pow};
use pouw_types::{
    BlockHeader, BlockId, ChainSpec, CumWork, Height, SpecError, Timestamp, block_id, block_work,
    check_genesis, parse_chain_spec,
};
use serde::de::DeserializeOwned;
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::{
    headers::{HeaderStore, StoreError},
    upstream::{Answer, Upstream, UpstreamError},
    verify::{VerifyError, accept},
};

/// The devnet chain spec of the repository, the one of the full node.
pub const DEVNET_SPEC: &str = include_str!("../../chainspec/devnet.json");

/// Deepest fork the light node follows, in headers, and the most headers of a branch it
/// reads at once.
pub const MAX_REORG: u64 = MAX_HEADERS_PER_CALL;

/// Time between two rounds of [`HeaderSync::run`].
pub const INTERVAL: Duration = Duration::from_secs(2);

/// What a round did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// No full node is ahead of the store.
    Synced,
    /// `added` headers were stored on top of the tip.
    Extended { added: u64 },
    /// `dropped` headers were removed from the tip and the `added` headers of a branch
    /// with more work took their place.
    Reorganized { dropped: u64, added: u64 },
    /// A full node is on a branch without more work than ours, so it is not followed.
    Kept,
}

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("no full node is configured")]
    NoNodes,
    #[error("the header store is empty, it has to be started first")]
    EmptyStore,
    #[error("full node: {0}")]
    Upstream(#[from] UpstreamError),
    #[error("a full node answered with status {0}")]
    Status(u16),
    #[error("a full node sent an unusable answer: {0}")]
    Invalid(String),
    #[error("the headers are of another chain, their genesis differs")]
    OtherGenesis,
    #[error("the fork is deeper than {} headers", MAX_REORG)]
    TooDeep,
    #[error(transparent)]
    Verify(#[from] VerifyError),
    #[error("header store: {0}")]
    Store(#[from] StoreError),
}

/// Why the chain spec cannot be loaded.
#[derive(Debug, Error)]
pub enum SpecLoadError {
    #[error("cannot read chain spec {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error(transparent)]
    Spec(#[from] SpecError),
}

/// Loads the chain spec at `path`, or the devnet spec when `None`, and returns it with
/// its genesis header.
///
/// # Errors
///
/// [`SpecLoadError::Read`] when the file cannot be read, [`SpecLoadError::Spec`] when it
/// is not a usable spec or its genesis id differs from `expected_genesis_id`.
pub fn load_chain(path: Option<&Path>) -> Result<(ChainSpec, BlockHeader), SpecLoadError> {
    let spec = match path {
        Some(path) => {
            let json = fs::read_to_string(path).map_err(|source| SpecLoadError::Read {
                path: path.to_owned(),
                source,
            })?;
            parse_chain_spec(&json)?
        }
        None => parse_chain_spec(DEVNET_SPEC)?,
    };
    let genesis = check_genesis(&spec)?;
    Ok((spec, genesis.header))
}

fn read(store: &RwLock<HeaderStore>) -> RwLockReadGuard<'_, HeaderStore> {
    store.read().unwrap_or_else(PoisonError::into_inner)
}

fn write(store: &RwLock<HeaderStore>) -> RwLockWriteGuard<'_, HeaderStore> {
    store.write().unwrap_or_else(PoisonError::into_inner)
}

fn clock() -> Timestamp {
    Timestamp(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs()),
    )
}

fn parse<T: DeserializeOwned>(answer: &Answer) -> Result<T, SyncError> {
    if answer.status != 200 {
        return Err(SyncError::Status(answer.status));
    }
    serde_json::from_slice(&answer.body).map_err(|error| SyncError::Invalid(error.to_string()))
}

fn count(items: &[BlockHeader]) -> u64 {
    u64::try_from(items.len()).unwrap_or(u64::MAX)
}

/// The work of `headers` together.
fn work_of(headers: &[BlockHeader]) -> Result<CumWork, SyncError> {
    headers.iter().try_fold(CumWork::ZERO, |sum, header| {
        sum.checked_add(block_work(&header.target))
            .ok_or_else(|| SyncError::Invalid("the work of the headers overflows".to_owned()))
    })
}

/// The headers of the store above `ancestor`, up to `tip`.
fn held_above(
    store: &RwLock<HeaderStore>,
    ancestor: u64,
    tip: u64,
) -> Result<Vec<BlockHeader>, SyncError> {
    let guard = read(store);
    let mut held = Vec::new();
    for height in ancestor.saturating_add(1)..=tip {
        let header = guard
            .get(Height(height))?
            .ok_or_else(|| StoreError::Corrupt(format!("no header at height {height}")))?;
        held.push(header);
    }
    Ok(held)
}

/// Follows the chain of `genesis` through the full nodes of an [`Upstream`].
#[derive(Debug)]
pub struct HeaderSync {
    params: ConsensusParams,
    genesis: BlockHeader,
    upstream: Upstream,
}

impl HeaderSync {
    pub fn new(params: ConsensusParams, genesis: BlockHeader, upstream: Upstream) -> Self {
        Self {
            params,
            genesis,
            upstream,
        }
    }

    /// Puts the genesis header in an empty store, and checks that a store with headers
    /// starts with it.
    ///
    /// # Errors
    ///
    /// [`SyncError::OtherGenesis`] when the store starts with another header,
    /// [`SyncError::Store`] when it cannot be read or written.
    pub fn start(&self, store: &mut HeaderStore) -> Result<(), SyncError> {
        match store.get(Height(0))? {
            None if store.is_empty() => {
                store.push(self.genesis)?;
                Ok(())
            }
            Some(stored) if block_id(&stored) == block_id(&self.genesis) => Ok(()),
            _ => Err(SyncError::OtherGenesis),
        }
    }

    /// Runs rounds, [`INTERVAL`] apart, until `stop` is set. A failing round is logged
    /// once for as long as it fails with the same message.
    pub fn run(&self, store: &RwLock<HeaderStore>, stop: &AtomicBool) {
        let mut last_error = String::new();
        while !stop.load(Ordering::Relaxed) {
            match self.step(store, clock()) {
                Ok(outcome) => {
                    last_error.clear();
                    match outcome {
                        Outcome::Extended { added } => info!(added, "headers added"),
                        Outcome::Reorganized { dropped, added } => {
                            info!(dropped, added, "the chain was reorganized");
                        }
                        Outcome::Kept => debug!("a full node is on a branch with less work"),
                        Outcome::Synced => {}
                    }
                }
                Err(error) => {
                    let text = error.to_string();
                    if text != last_error {
                        warn!(%error, "cannot sync the headers");
                        last_error = text;
                    }
                }
            }
            thread::sleep(INTERVAL);
        }
    }

    /// One round over the full nodes, at the time `now` for the clock rule of the
    /// headers. The first node that gives headers ends the round, the others are asked
    /// only when it has none.
    ///
    /// # Errors
    ///
    /// The last error when no full node could be followed, [`SyncError::NoNodes`] when
    /// none is configured.
    pub fn step(&self, store: &RwLock<HeaderStore>, now: Timestamp) -> Result<Outcome, SyncError> {
        let (mut synced, mut kept) = (false, false);
        let mut last = None;
        for node in 0..self.upstream.len() {
            match self.follow(node, store, now) {
                Ok(done @ (Outcome::Extended { .. } | Outcome::Reorganized { .. })) => {
                    return Ok(done);
                }
                Ok(Outcome::Synced) => synced = true,
                Ok(Outcome::Kept) => kept = true,
                Err(error) => {
                    warn!(node, %error, "this full node cannot be followed");
                    last = Some(error);
                }
            }
        }
        if synced {
            Ok(Outcome::Synced)
        } else if kept {
            Ok(Outcome::Kept)
        } else {
            Err(last.unwrap_or(SyncError::NoNodes))
        }
    }

    fn follow(
        &self,
        node: usize,
        store: &RwLock<HeaderStore>,
        now: Timestamp,
    ) -> Result<Outcome, SyncError> {
        let head = self.head_of(node)?;
        let head_height = head.header.height.get();
        let (tip, _) = read(store).tip().ok_or(SyncError::EmptyStore)?;
        if read(store).find(&head.id)?.is_some() {
            return Ok(Outcome::Synced);
        }
        let ancestor = self.ancestor(node, store, head_height.min(tip.0), tip.0)?;
        if ancestor == tip.0 {
            self.extend(node, store, now, head_height)
        } else {
            self.switch(node, store, now, ancestor, head_height)
        }
    }

    /// The head of a full node, as a header with its id.
    fn head_of(&self, node: usize) -> Result<HeaderView, SyncError> {
        let answer = self.upstream.get_from(node, HEAD, true)?;
        let view: HeaderView = parse(&answer)?;
        if view.id != block_id(&view.header) {
            return Err(SyncError::Invalid(
                "the id of the head is not the id of its header".to_owned(),
            ));
        }
        if view.header.chain_id.get() != self.params.chain_id.0 {
            return Err(SyncError::Invalid(
                "the head is of another chain".to_owned(),
            ));
        }
        Ok(view)
    }

    /// The headers `from..=to` of a full node. They are ascending from `from`, each one
    /// has the id it is named by, and each one is the child of the one before. The
    /// answer may stop short of `to`.
    fn headers_page(&self, node: usize, from: u64, to: u64) -> Result<Vec<BlockHeader>, SyncError> {
        let path = format!("{HEADERS}?from={from}&to={to}");
        let page: HeadersPage = parse(&self.upstream.get_from(node, &path, true)?)?;
        let wanted = to.saturating_sub(from).saturating_add(1);
        if u64::try_from(page.headers.len()).unwrap_or(u64::MAX) > wanted {
            return Err(SyncError::Invalid(
                "more headers than were asked for".to_owned(),
            ));
        }
        let mut headers = Vec::with_capacity(page.headers.len());
        let mut expected = from;
        let mut previous: Option<BlockId> = None;
        for view in page.headers {
            let id = block_id(&view.header);
            let linked = previous.is_none_or(|previous| view.header.parent == previous);
            if view.id != id || view.header.height.get() != expected || !linked {
                return Err(SyncError::Invalid(
                    "a header is out of order, wrongly named or not linked to the one before"
                        .to_owned(),
                ));
            }
            previous = Some(id);
            expected = expected.saturating_add(1);
            headers.push(view.header);
        }
        Ok(headers)
    }

    /// Whether the full node and the store hold the same header at `height`.
    fn agrees(
        &self,
        node: usize,
        store: &RwLock<HeaderStore>,
        height: u64,
    ) -> Result<bool, SyncError> {
        let page = self.headers_page(node, height, height)?;
        let theirs = page.first().ok_or_else(|| {
            SyncError::Invalid("the full node lacks a header it has announced".to_owned())
        })?;
        let ours = read(store).get(Height(height))?;
        Ok(ours.is_some_and(|ours| block_id(&ours) == block_id(theirs)))
    }

    /// The height of the last header the full node and the store hold both, searched
    /// from `top` down: probes `top - 1`, `top - 2`, `top - 4`, ... until one agrees, then
    /// a binary search between that one and the last that did not. `tip` is the height of
    /// the tip of the store, which bounds the depth of the search.
    fn ancestor(
        &self,
        node: usize,
        store: &RwLock<HeaderStore>,
        top: u64,
        tip: u64,
    ) -> Result<u64, SyncError> {
        if self.agrees(node, store, top)? {
            return Ok(top);
        }
        let mut bad = top;
        let mut step = 1_u64;
        let mut good = loop {
            if bad == 0 {
                return Err(SyncError::OtherGenesis);
            }
            if tip.saturating_sub(bad) >= MAX_REORG {
                return Err(SyncError::TooDeep);
            }
            let probe = top.saturating_sub(step);
            if self.agrees(node, store, probe)? {
                break probe;
            }
            bad = probe;
            step = step.saturating_mul(2);
        };
        while good.saturating_add(1) < bad {
            let middle = good.saturating_add(bad.saturating_sub(good) / 2);
            if self.agrees(node, store, middle)? {
                good = middle;
            } else {
                bad = middle;
            }
        }
        Ok(good)
    }

    /// The full node is ahead on our chain: reads the headers above our tip, a range at
    /// a time, and stores each one after it verified.
    fn extend(
        &self,
        node: usize,
        store: &RwLock<HeaderStore>,
        now: Timestamp,
        head_height: u64,
    ) -> Result<Outcome, SyncError> {
        let mut added = 0_u64;
        loop {
            let (tip, tip_id) = read(store).tip().ok_or(SyncError::EmptyStore)?;
            if tip.0 >= head_height {
                break;
            }
            let next = tip.0.saturating_add(1);
            let to = head_height.min(next.saturating_add(MAX_HEADERS_PER_CALL.saturating_sub(1)));
            let page = self.headers_page(node, next, to)?;
            if page.first().is_none_or(|first| first.parent != tip_id) {
                return Err(SyncError::Invalid(
                    "the headers do not follow our tip".to_owned(),
                ));
            }
            let mut guard = write(store);
            for header in page {
                accept(&mut guard, &self.params, now, header)?;
                added = added.saturating_add(1);
            }
        }
        Ok(Outcome::Extended { added })
    }

    /// The full node is on another branch that leaves ours at `ancestor`. The branch
    /// replaces ours when it holds more work.
    fn switch(
        &self,
        node: usize,
        store: &RwLock<HeaderStore>,
        now: Timestamp,
        ancestor: u64,
        head_height: u64,
    ) -> Result<Outcome, SyncError> {
        let to = head_height.min(ancestor.saturating_add(MAX_REORG));
        let branch = self.headers_page(node, ancestor.saturating_add(1), to)?;
        let held = read(store).get(Height(ancestor))?.ok_or_else(|| {
            StoreError::Corrupt(format!("no header at the ancestor height {ancestor}"))
        })?;
        if branch
            .first()
            .is_none_or(|first| first.parent != block_id(&held))
        {
            return Err(SyncError::Invalid(
                "the branch does not start at the common ancestor".to_owned(),
            ));
        }
        for header in &branch {
            check_pow(&self.params, header).map_err(VerifyError::from)?;
        }
        let (tip, _) = read(store).tip().ok_or(SyncError::EmptyStore)?;
        let ours = held_above(store, ancestor, tip.0)?;
        if work_of(&branch)? <= work_of(&ours)? {
            return Ok(Outcome::Kept);
        }
        let mut guard = write(store);
        let mut removed = Vec::new();
        while guard.tip().is_some_and(|(height, _)| height.0 > ancestor) {
            let Some(header) = guard.pop()? else { break };
            removed.push(header);
        }
        let dropped = count(&removed);
        let applied: Result<(), VerifyError> = branch
            .iter()
            .try_for_each(|header| accept(&mut guard, &self.params, now, *header));
        if let Err(error) = applied {
            while guard.tip().is_some_and(|(height, _)| height.0 > ancestor) {
                guard.pop()?;
            }
            for header in removed.into_iter().rev() {
                guard.push(header)?;
            }
            return Err(error.into());
        }
        Ok(Outcome::Reorganized {
            dropped,
            added: count(&branch),
        })
    }
}

#[cfg(test)]
mod tests;
