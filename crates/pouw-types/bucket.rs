//! The bucket of a proof request, `contracts/block.md` section "Bucket": a miner includes
//! only the requests of one bucket, selected by a prefix of the request hash
//! (`SNARKChain` Sec. IV-B5). The miner picks its requests with it and validation checks
//! the requests of a block with it, so both use this one function.

use crate::TxId;

/// The number of buckets `k` until the rule for it is decided (pouw-docs#11). One bucket
/// holds every request, so the split does nothing yet.
pub const TEMPORARY_BUCKET_COUNT: u32 = 1;

/// The bucket of the request `id` among `bucket_count` buckets: the first 4 bytes of the
/// txid read as a little-endian `u32`, modulo `bucket_count`. `None` for a `bucket_count`
/// of 0, which no header may carry.
pub fn bucket(id: &TxId, bucket_count: u32) -> Option<u32> {
    let [a, b, c, d, ..] = id.hash().0;
    u32::from_le_bytes([a, b, c, d]).checked_rem(bucket_count)
}
