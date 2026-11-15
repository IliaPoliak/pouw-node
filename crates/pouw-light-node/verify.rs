//! Verification of a header against the headers the light node holds (pouw-node#103).
//! The rules are those of the full node and come from the same functions of
//! `pouw-consensus`: version, chain id, height, parent, the target of the schedule and
//! the timestamp bounds (`check_header`), then the proof of work (`check_pow`). The
//! light node checks no body and no proof tx, it has none.
//!
//! The target rule is scheduled from block 1 and from the genesis timestamp, so the
//! store must hold the chain from genesis. A store that starts at a later checkpoint
//! cannot verify and says so with [`VerifyError::NoGenesis`].

use pouw_consensus::{
    Anchor, ConsensusParams, HeaderContext, InvalidBlock, PowError, check_header, check_pow,
    median_time_past, timestamp::MTP_WINDOW,
};
use pouw_types::{BlockHeader, Height, Timestamp};
use thiserror::Error;

use crate::headers::{HeaderStore, StoreError};

#[derive(Debug, Error)]
pub enum VerifyError {
    /// There is no parent to check against: the genesis header has to be stored first.
    #[error("the header store is empty, it needs the genesis header first")]
    EmptyStore,
    /// The store does not start at genesis, so the anchor of the target rule is missing.
    #[error("the stored headers start at height {0}, the target rule needs them from genesis")]
    NoGenesis(u64),
    #[error("header store: {0}")]
    Store(#[from] StoreError),
    /// A rule of the header that needs its parent.
    #[error("invalid header: {0}")]
    Header(#[from] InvalidBlock),
    #[error("proof of work: {0}")]
    Pow(#[from] PowError),
}

fn stored(store: &HeaderStore, height: u64) -> Result<BlockHeader, VerifyError> {
    store
        .get(Height(height))?
        .ok_or_else(|| StoreError::Corrupt(format!("no header at height {height}")).into())
}

/// The anchor of the target rule and the median time past of the chain ending in
/// `parent`, as the full node computes them for the canonical chain.
fn ancestry(
    store: &HeaderStore,
    params: &ConsensusParams,
    parent: &BlockHeader,
) -> Result<(Anchor, Timestamp), VerifyError> {
    let parent_height = parent.height.get();
    if parent_height == 0 {
        let times = [Timestamp(parent.timestamp.get())];
        return Ok((
            Anchor::first_block(params, parent),
            median_time_past(&times),
        ));
    }
    let window = u64::try_from(MTP_WINDOW).unwrap_or(u64::MAX);
    let start = parent_height.saturating_sub(window.saturating_sub(1));
    let mut times = Vec::new();
    for height in start..=parent_height {
        times.push(Timestamp(stored(store, height)?.timestamp.get()));
    }
    let first = stored(store, 1)?;
    let genesis = stored(store, 0)?;
    Ok((
        Anchor::from_block(&first, &genesis),
        median_time_past(&times),
    ))
}

/// Checks that `header` is a valid child of the tip of `store` at the time `now`: the
/// rules of the header that need its parent, then its proof of work. Nothing is stored.
///
/// # Errors
///
/// [`VerifyError::EmptyStore`] and [`VerifyError::NoGenesis`] when the store cannot
/// verify, [`VerifyError::Header`] or [`VerifyError::Pow`] with the rule that fails,
/// [`VerifyError::Store`] when the store cannot be read.
pub fn verify(
    store: &HeaderStore,
    params: &ConsensusParams,
    now: Timestamp,
    header: &BlockHeader,
) -> Result<(), VerifyError> {
    let (tip_height, _) = store.tip().ok_or(VerifyError::EmptyStore)?;
    if let Some(first) = store.first_height()
        && first.0 != 0
    {
        return Err(VerifyError::NoGenesis(first.0));
    }
    let parent = stored(store, tip_height.0)?;
    let (anchor, mtp) = ancestry(store, params, &parent)?;
    let context = HeaderContext {
        params,
        anchor: &anchor,
        mtp,
        now,
    };
    check_header(&context, &parent, header)?;
    check_pow(params, header)?;
    Ok(())
}

/// [`verify`] and then append `header` to `store`. A header that fails is not stored.
///
/// # Errors
///
/// As [`verify`], and [`VerifyError::Store`] when the append fails.
pub fn accept(
    store: &mut HeaderStore,
    params: &ConsensusParams,
    now: Timestamp,
    header: BlockHeader,
) -> Result<(), VerifyError> {
    verify(store, params, now, &header)?;
    store.push(header)?;
    Ok(())
}

#[cfg(test)]
mod tests;
