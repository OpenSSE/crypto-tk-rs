use std::ops::Bound::*;
use std::ops::{Bound, RangeBounds};

use zeroize::Zeroize;

/// Structure encoding the domain of a range-constrained PRF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RCPrfRange {
    pub(crate) range: std::ops::RangeInclusive<u64>,
}

impl From<std::ops::Range<u64>> for RCPrfRange {
    fn from(range: std::ops::Range<u64>) -> Self {
        if range.end == range.start {
            panic!("Invalid empty input range");
        }
        RCPrfRange::from(range.start..=(range.end - 1))
    }
}

impl From<std::ops::RangeInclusive<u64>> for RCPrfRange {
    fn from(range: std::ops::RangeInclusive<u64>) -> Self {
        RCPrfRange { range }
    }
}

impl RangeBounds<u64> for RCPrfRange {
    fn start_bound(&self) -> Bound<&u64> {
        self.range.start_bound()
    }

    fn end_bound(&self) -> Bound<&u64> {
        self.range.end_bound()
    }
}

impl std::fmt::Display for RCPrfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, {}]", self.min(), self.max())
    }
}

impl Zeroize for RCPrfRange {
    fn zeroize(&mut self) {
        self.range = 0..=0;
    }
}

impl RCPrfRange {
    /// Creates a new range spanning from `min` to `max` (included).
    ///
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// assert_eq!(RCPrfRange::new(4,6), RCPrfRange::from(4..7));
    /// ```
    pub fn new(min: u64, max: u64) -> Self {
        RCPrfRange { range: (min..=max) }
    }

    /// Returns the minimum value in the range
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// assert_eq!(range.min(), 4);
    /// ```
    ///
    pub fn min(&self) -> u64 {
        *self.range.start()
    }

    /// Returns the maximum value in the range
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// assert_eq!(range.max(), 6);
    /// ```
    ///
    pub fn max(&self) -> u64 {
        *self.range.end()
    }

    /// Returns the width of the range
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// assert_eq!(range.width(), 3);
    /// ```
    pub fn width(&self) -> u64 {
        self.max() - self.min() + 1
    }

    /// Returns `true` if the range contains `leaf`
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// assert!(!range.contains_leaf(3));
    /// assert!(range.contains_leaf(4));
    /// assert!(range.contains_leaf(5));
    /// assert!(range.contains_leaf(6));
    /// assert!(!range.contains_leaf(7));
    /// ```
    pub fn contains_leaf(&self, leaf: u64) -> bool {
        (leaf >= self.min()) && (leaf <= self.max())
    }

    /// Returns `true` if the two ranges intersect
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// assert!(!range.intersects(&(2..3)));
    /// assert!(!range.intersects(&(2..4)));
    /// assert!(range.intersects(&(2..=4)));
    /// assert!(range.intersects(&RCPrfRange::from(2..5)));
    /// assert!(range.intersects(&RCPrfRange::from(5..6)));
    /// assert!(range.intersects(&RCPrfRange::from(6..8)));
    /// assert!(!range.intersects(&RCPrfRange::from(7..8)));
    /// assert!(!range.intersects(&RCPrfRange::from(9..10)));
    /// assert!(!range.intersects(&(0..0)));
    /// ```
    pub fn intersects<R>(&self, r: &R) -> bool
    where
        R: RangeBounds<u64>,
    {
        let cond1: bool = match r.start_bound() {
            Unbounded => true,
            Included(&a) => self.max() >= a,
            Excluded(&a) => self.max() > a,
        };

        let cond2: bool = match r.end_bound() {
            Unbounded => true,
            Included(&a) => self.min() <= a,
            Excluded(&a) => self.min() < a,
        };

        cond1 && cond2
    }

    /// Returns the intersection with `r` or `None` if ranges do
    ///  not intersect.
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// assert_eq!(range.intersection(&(2..3)), None);
    /// assert_eq!(range.intersection(&(2..4)), None);
    /// assert_eq!(range.intersection(&(2..=4)), Some(RCPrfRange::new(4,4)));
    /// assert_eq!(range.intersection(&RCPrfRange::from(2..5)), Some(RCPrfRange::new(4,4)));
    /// assert_eq!(range.intersection(&RCPrfRange::from(5..6)), Some(RCPrfRange::new(5,5)));
    /// assert_eq!(range.intersection(&RCPrfRange::from(6..8)), Some(RCPrfRange::new(6,6)));
    /// assert_eq!(range.intersection(&RCPrfRange::from(7..8)), None);
    /// assert_eq!(range.intersection(&RCPrfRange::from(9..10)), None);
    /// assert_eq!(range.intersection(&(0..0)), None);
    /// ```
    ///
    pub fn intersection<R>(&self, r: &R) -> Option<RCPrfRange>
    where
        R: RangeBounds<u64>,
    {
        let mut intersects = true;
        let r_start: u64 = match r.start_bound() {
            Unbounded => 0,
            Included(&a) if self.max() >= a => a,
            Excluded(&a) if self.max() > a => a + 1, // if the condition is true, we are sure that a+1 is not overflowing
            _ => {
                intersects = false;
                0
            }
        };

        let r_end: u64 = match r.end_bound() {
            Unbounded => u64::max_value(),
            Included(&a) if self.min() <= a => a,
            Excluded(&a) if self.min() < a => a - 1, // if the condition is true, we are sure that a-1 is not underflowing
            _ => {
                intersects = false;
                0
            }
        };

        if intersects {
            Some(RCPrfRange::new(
                r_start.max(self.min()),
                r_end.min(self.max()),
            ))
        } else {
            None
        }
    }
    /// Returns `true` if `r` is contained in the range
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RCPrfRange;
    /// let range = RCPrfRange::from(4..7);
    /// assert!(!range.contains_range(&RCPrfRange::from(2..3)));
    /// assert!(!range.contains_range(&(2..4)));
    /// assert!(!range.contains_range(&(3..6)));
    /// assert!(range.contains_range(&(4..6)));
    /// assert!(range.contains_range(&(4..=6)));
    /// assert!(range.contains_range(&(5..6)));
    /// assert!(range.contains_range(&(5..7)));
    /// assert!(range.contains_range(&(4..6)));
    /// assert!(range.contains_range(&(4..7)));
    /// assert!(!range.contains_range(&(5..8)));
    /// assert!(!range.contains_range(&(..6)));
    /// assert!(!range.contains_range(&(6..)));
    /// ```
    pub fn contains_range<R>(&self, r: &R) -> bool
    where
        R: RangeBounds<u64>,
    {
        let cond1: bool = match r.start_bound() {
            Unbounded => self.min() == 0,
            Included(&a) => self.min() <= a,
            Excluded(&a) => self.min() < a,
        };

        let cond2: bool = match r.end_bound() {
            Unbounded => self.max() == u64::max_value(),
            Included(&a) => self.max() >= a,
            Excluded(&0) => false,
            Excluded(&a) => self.max() >= a - 1,
        };

        cond1 && cond2
    }
}
