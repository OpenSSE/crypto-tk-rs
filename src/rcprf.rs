//! Range-constrained PRF

use crate::key::{Key, Key256, KeyAccessor};
use crate::prf::Prf;

use clear_on_drop::clear::Clear;
use zeroize::Zeroize;

/// Range-constrained pseudo-random functions
///
/// ## Concept
///
/// The point of range-constrained pseudo-random functions (RC-PRF) is to have PRFs for which you can restrict the evaluation to a specific range. In practice, you call a `constrain` algorithm on the RC-PRF, with a range argument `(a..b)`, and get a PRF-like object that you can evaluate on integer in the range `[a, b-1]`.
///
/// Our RC-PRF implementation is based on a tree construction, similar to the Goldreich-Goldwasser-Micali construction.
///

// Type encoding a choice of child in a binary tree.
enum RCPrfTreeNodeChild {
    LeftChild = 0,
    RightChild = 1,
}

const KEY_SIZE: u8 = 32u8;

/// Maximum tree height of a RCPRF tree
pub const MAX_HEIGHT: u8 = 65;

/// Returns the maximum leaf index for a RCPRF using a tree of height `height`. It returns 0 for a tree of height 0 and 2^64-1 for a `height` larger or equal to `MAX_HEIGHT` (65)
pub const fn max_leaf_index(height: u8) -> u64 {
    if height == 0 {
        return 0;
    }
    if height >= MAX_HEIGHT {
        return 0xFFFFFFFFFFFFFFFF;
    }
    return (1u64 << (height - 1)) - 1;
    // max_leaf_index_generic(height);
}

/// Structure encoding the domain of a range-constrained PRF.
pub struct RCPrfRange {
    range: std::ops::Range<u64>,
}

impl From<std::ops::Range<u64>> for RCPrfRange {
    fn from(range: std::ops::Range<u64>) -> Self {
        RCPrfRange { range }
    }
}
impl RCPrfRange {
    /// Returns `true` if the range contains `leaf`
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// # assert!(!range.contains_leaf(3));
    /// # assert!(range.contains_leaf(4));
    /// # assert!(range.contains_leaf(5));
    /// # assert!(range.contains_leaf(6));
    /// # assert!(!range.contains_leaf(7));
    /// ```
    pub fn contains_leaf(&self, leaf: u64) -> bool {
        (leaf >= self.range.start) && (leaf < self.range.end)
    }

    /// Returns `true` if the two ranges intersect
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// # assert!(!range.intersects(&RCPrfRange::from(2..3)));
    /// # assert!(!range.intersects(&RCPrfRange::from(2..4)));
    /// # assert!(range.intersects(&RCPrfRange::from(2..5)));
    /// # assert!(range.intersects(&RCPrfRange::from(5..6)));
    /// # assert!(range.intersects(&RCPrfRange::from(6..8)));
    /// # assert!(!range.intersects(&RCPrfRange::from(7..8)));
    /// ```
    pub fn intersects(&self, r: &RCPrfRange) -> bool {
        (self.range.start < r.range.end) && (r.range.start < self.range.end)
    }

    /// Returns `true` if the two ranges intersect
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// assert!(!range.intersects_range(&(2..3)));
    /// assert!(!range.intersects_range(&(2..4)));
    /// assert!(range.intersects_range(&(2..5)));
    /// assert!(range.intersects_range(&(5..6)));
    /// assert!(range.intersects_range(&(6..8)));
    /// assert!(!range.intersects_range(&(7..8)));
    /// ```
    pub fn intersects_range(&self, r: &std::ops::Range<u64>) -> bool {
        (self.range.start < r.end) && (r.start < self.range.end)
    }

    /// Returns `true` if `r` is contained in the range
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// # assert!(!range.contains(&RCPrfRange::from(2..3)));
    /// # assert!(!range.contains(&RCPrfRange::from(2..4)));
    /// # assert!(range.contains(&RCPrfRange::from(5..6)));
    /// # assert!(range.contains(&RCPrfRange::from(5..7)));
    /// # assert!(range.contains(&RCPrfRange::from(4..6)));
    /// # assert!(range.contains(&RCPrfRange::from(4..7)));
    /// # assert!(!range.contains(&RCPrfRange::from(5..8)));
    /// ```
    pub fn contains(&self, r: &RCPrfRange) -> bool {
        (r.range.start >= self.range.start) && (r.range.end <= self.range.end)
    }
}
