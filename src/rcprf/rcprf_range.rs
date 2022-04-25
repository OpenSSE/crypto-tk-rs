use crate::serialization::cleartext_serialization::*;
use crate::serialization::errors::CleartextContentDeserializationError;
// use std::ops::Bound::*;
use std::ops::{Bound, RangeBounds};

use zeroize::Zeroize;

/// Structure encoding the domain of a range-constrained PRF.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RcPrfRange {
    pub(crate) range: std::ops::RangeInclusive<u64>,
}

impl From<std::ops::Range<u64>> for RcPrfRange {
    fn from(range: std::ops::Range<u64>) -> Self {
        assert!(
            range.end != range.start,
            "Invalid empty input range ({} .. {})",
            range.start,
            range.end
        );

        RcPrfRange::new(range.start, range.end - 1)
    }
}

impl From<std::ops::RangeInclusive<u64>> for RcPrfRange {
    fn from(range: std::ops::RangeInclusive<u64>) -> Self {
        RcPrfRange::new(*range.start(), *range.end())

        // RcPrfRange { range }
    }
}

impl RangeBounds<u64> for RcPrfRange {
    fn start_bound(&self) -> Bound<&u64> {
        self.range.start_bound()
    }

    fn end_bound(&self) -> Bound<&u64> {
        self.range.end_bound()
    }
}

impl std::fmt::Display for RcPrfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}, {}]", self.min(), self.max())
    }
}

impl Zeroize for RcPrfRange {
    fn zeroize(&mut self) {
        self.range = 0..=0;
    }
}

impl RcPrfRange {
    /// Creates a new range spanning from `min` to `max` (included).
    ///
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RcPrfRange;
    /// assert_eq!(RcPrfRange::new(4,6), RcPrfRange::from(4..7));
    /// ```
    #[must_use]
    pub fn new(min: u64, max: u64) -> Self {
        assert!(min <= max, "Invalid range input");
        RcPrfRange { range: (min..=max) }
    }

    /// Returns the minimum value in the range
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RcPrfRange;
    /// let range = RcPrfRange::from(4..7);
    /// assert_eq!(range.min(), 4);
    /// ```
    #[must_use]
    pub fn min(&self) -> u64 {
        *self.range.start()
    }

    /// Returns the maximum value in the range
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RcPrfRange;
    /// let range = RcPrfRange::from(4..7);
    /// assert_eq!(range.max(), 6);
    /// ```
    #[must_use]
    pub fn max(&self) -> u64 {
        *self.range.end()
    }

    /// Returns the width of the range
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RcPrfRange;
    /// let range = RcPrfRange::from(4..7);
    /// assert_eq!(range.width(), 3);
    /// ```
    #[must_use]
    pub fn width(&self) -> u64 {
        self.max() - self.min() + 1
    }

    /// Returns `true` if the range contains `leaf`
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RcPrfRange;
    /// let range = RcPrfRange::from(4..7);
    /// assert!(!range.contains_leaf(3));
    /// assert!(range.contains_leaf(4));
    /// assert!(range.contains_leaf(5));
    /// assert!(range.contains_leaf(6));
    /// assert!(!range.contains_leaf(7));
    /// ```
    #[must_use]
    pub fn contains_leaf(&self, leaf: u64) -> bool {
        (leaf >= self.min()) && (leaf <= self.max())
    }

    /// Returns `true` if the two ranges intersect
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RcPrfRange;
    /// let range = RcPrfRange::from(4..7);
    /// assert!(!range.intersects(&(2..3)));
    /// assert!(!range.intersects(&(2..4)));
    /// assert!(range.intersects(&(2..=4)));
    /// assert!(range.intersects(&RcPrfRange::from(2..5)));
    /// assert!(range.intersects(&RcPrfRange::from(5..6)));
    /// assert!(range.intersects(&RcPrfRange::from(6..8)));
    /// assert!(!range.intersects(&RcPrfRange::from(7..8)));
    /// assert!(!range.intersects(&RcPrfRange::from(9..10)));
    /// assert!(!range.intersects(&(0..0)));
    /// ```
    pub fn intersects<R>(&self, r: &R) -> bool
    where
        R: RangeBounds<u64>,
    {
        let cond1: bool = match r.start_bound() {
            Bound::Unbounded => true,
            Bound::Included(&a) => self.max() >= a,
            Bound::Excluded(&a) => self.max() > a,
        };

        let cond2: bool = match r.end_bound() {
            Bound::Unbounded => true,
            Bound::Included(&a) => self.min() <= a,
            Bound::Excluded(&a) => self.min() < a,
        };

        cond1 && cond2
    }

    /// Returns the intersection with `r` or `None` if ranges do
    ///  not intersect.
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RcPrfRange;
    /// let range = RcPrfRange::from(4..7);
    /// assert_eq!(range.intersection(&(2..3)), None);
    /// assert_eq!(range.intersection(&(2..4)), None);
    /// assert_eq!(range.intersection(&(2..=4)), Some(RcPrfRange::new(4,4)));
    /// assert_eq!(range.intersection(&RcPrfRange::from(2..5)), Some(RcPrfRange::new(4,4)));
    /// assert_eq!(range.intersection(&RcPrfRange::from(5..6)), Some(RcPrfRange::new(5,5)));
    /// assert_eq!(range.intersection(&RcPrfRange::from(6..8)), Some(RcPrfRange::new(6,6)));
    /// assert_eq!(range.intersection(&RcPrfRange::from(7..8)), None);
    /// assert_eq!(range.intersection(&RcPrfRange::from(9..10)), None);
    /// assert_eq!(range.intersection(&(0..0)), None);
    /// ```
    pub fn intersection<R>(&self, r: &R) -> Option<RcPrfRange>
    where
        R: RangeBounds<u64>,
    {
        let mut intersects = true;
        let r_start: u64 = match r.start_bound() {
            Bound::Unbounded => 0,
            Bound::Included(&a) if self.max() >= a => a,
            Bound::Excluded(&a) if self.max() > a => a + 1,
            // if the condition is true, we are sure that a+1 is not overflowing
            _ => {
                intersects = false;
                0
            }
        };

        let r_end: u64 = match r.end_bound() {
            Bound::Unbounded => u64::max_value(),
            Bound::Included(&a) if self.min() <= a => a,
            Bound::Excluded(&a) if self.min() < a => a - 1,
            // if the condition is true, we are sure that a-1 is not
            // underflowing
            _ => {
                intersects = false;
                0
            }
        };

        intersects.then(|| {
            RcPrfRange::new(r_start.max(self.min()), r_end.min(self.max()))
        })
    }
    /// Returns `true` if `r` is contained in the range
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::RcPrfRange;
    /// let range = RcPrfRange::from(4..7);
    /// assert!(!range.contains_range(&RcPrfRange::from(2..3)));
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
            Bound::Unbounded => self.min() == 0,
            Bound::Included(&a) => self.min() <= a,
            Bound::Excluded(&a) => self.min() < a,
        };

        let cond2: bool = match r.end_bound() {
            Bound::Unbounded => self.max() == u64::max_value(),
            Bound::Included(&a) => self.max() >= a,
            Bound::Excluded(&0) => false,
            Bound::Excluded(&a) => self.max() >= a - 1,
        };

        cond1 && cond2
    }
}

impl SerializableCleartextContent for RcPrfRange {
    fn serialization_content_byte_size(&self) -> usize {
        2 * std::mem::size_of::<u64>()
    }
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        writer.write_all(&self.min().to_le_bytes())?;
        writer.write_all(&self.max().to_le_bytes())?;

        Ok(self.serialization_content_byte_size())
    }
}

impl DeserializableCleartextContent for RcPrfRange {
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        let mut min_bytes = [0u8; 8];
        reader.read_exact(&mut min_bytes)?;
        let min = u64::from_le_bytes(min_bytes);

        let mut max_bytes = [0u8; 8];
        reader.read_exact(&mut max_bytes)?;
        let max = u64::from_le_bytes(max_bytes);

        Ok(RcPrfRange::new(min, max))
    }
}
