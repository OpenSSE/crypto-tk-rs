use crate::rcprf::rcprf_range::*;
use thiserror::Error;

/// RCPRF-related errors
#[derive(Error, Debug)]
pub enum RcPrfError {
    /// Invalid evaluation point error (point out of range)
    #[error("Evaluation point {0} outside of valid range {1}")]
    InvalidEvalPoint(u64, RcPrfRange),
    /// Invalid evaluation range error (out of range)
    #[error(
        "Invalid evaluation range: {0} is not contained in the valid range {1}"
    )]
    InvalidEvalRange(RcPrfRange, RcPrfRange),
    /// Invalid range width
    #[error("Incompatible range width ({0}) and outputs length ({1}).")]
    InvalidRangeWidth(usize, u64),
    /// Invalid constrain range error ( out of range)
    #[error(
        "Invalid constrain range: {0} is not contained in the valid range {1}"
    )]
    InvalidConstrainRange(RcPrfRange, RcPrfRange),
    /// Invalid tree height (height is too large)
    #[error(
        "Invalid tree height: height ({0}) is too large. The maximum height is {1}."
    )]
    InvalidTreeHeight(u8, u8),
    /// Non-consecutive merge ranges
    #[error(
        "Ranges of the RcPrfs to be merged ({0} and {1}) are not consecutive."
    )]
    NonConsecutiveMergeRanges(RcPrfRange, RcPrfRange),
}
