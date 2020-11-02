//! Range-constrained PRF

use crate::key::Key256;
use crate::prg::KeyDerivationPrg;
use crate::Prf;

// use clear_on_drop::clear::Clear;
// use zeroize::Zeroize;

use std::ops::Bound::*;
use std::ops::{Bound, RangeBounds};

/// Range-constrained pseudo-random functions
///
/// ## Concept
///
/// The point of range-constrained pseudo-random functions (RC-PRF) is to have PRFs for which you can restrict the evaluation to a specific range. In practice, you call a `constrain` algorithm on the RC-PRF, with a range argument `(a..b)`, and get a PRF-like object that you can evaluate on integer in the range `[a, b-1]`.
///
/// Our RC-PRF implementation is based on a tree construction, similar to the Goldreich-Goldwasser-Micali construction.
///

// Type encoding a choice of child in a binary tree.
#[derive(Clone, Copy, Debug)]
enum RCPrfTreeNodeChild {
    LeftChild = 0,
    RightChild = 1,
}

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
    (1u64 << (height - 1)) - 1
}

/// Structure encoding the domain of a range-constrained PRF.
#[derive(Clone, Debug)]
pub struct RCPrfRange {
    range: std::ops::RangeInclusive<u64>,
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

impl RCPrfRange {
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

struct ConstrainedRCPrfInnerElement {
    prg: KeyDerivationPrg<Key256>,
    range: RCPrfRange,
    subtree_height: u8,
    rcprf_height: u8,
}

struct ConstrainedRCPrfLevel1Element {
    prf: Prf,
    range: RCPrfRange,
    rcprf_height: u8,
}

/// An *unconstrained* RCPrf object
pub struct RCPrf {
    root: ConstrainedRCPrfInnerElement,
}

/// A *constrained* RCPrf object (obtained after constraining a RCPrf - constrained or not)
pub struct ConstrainedRCPrf {
    elements: Vec<Box<dyn RCPrfElement>>,
}

/// Trait representing a PRF that can be evaluated on an integral range
pub trait RangePrf {
    /// Returns the range on which the PRF can be evaluated
    fn range(&self) -> RCPrfRange;

    /// Evaluate the PRF on the input `x` and put the result in `output`.
    /// Returns an error when the input is out of the PRF range.
    fn eval(&self, x: u64, output: &mut [u8]) -> Result<(), String>;

    /// Evaluate the PRF on every value of the `range` and put the result in
    /// `outputs` such that the i-th value of the range is put at the i-th
    /// position of the output.
    /// Returns an error when `range` is not contained in the PRF's range.
    fn eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String>;

    /// Constrain the PRF on `range`.
    /// Returns an error if `range` does not intersect the PRF's range
    fn constrain(&self, range: &RCPrfRange)
        -> Result<ConstrainedRCPrf, String>;
}

/// Trait representing a PRF built on a tree structure
pub trait TreeBasedPrf {
    /// Returns the height of the underlying tree of the PRF.
    /// For range constrained PRFs, this stays the same when constraining the
    /// PRF.
    fn tree_height(&self) -> u8;
}

trait RCPrfElement: TreeBasedPrf {
    fn is_leaf(&self) -> bool;
    fn subtree_height(&self) -> u8;

    fn get_child_node(&self, leaf: u64, node_depth: u8) -> RCPrfTreeNodeChild {
        // the -2 term comes from two facts:
        // - the minimum valid tree height is 1 (single note)
        // - the maximum depth of a node is tree_height-1
        let mask = 1u64 << (self.tree_height() - node_depth - 2);

        if (leaf & mask) == 0 {
            RCPrfTreeNodeChild::LeftChild
        } else {
            RCPrfTreeNodeChild::RightChild
        }
    }
}

impl TreeBasedPrf for ConstrainedRCPrfLevel1Element {
    fn tree_height(&self) -> u8 {
        self.rcprf_height
    }
}

impl RCPrfElement for ConstrainedRCPrfLevel1Element {
    fn is_leaf(&self) -> bool {
        true
    }

    fn subtree_height(&self) -> u8 {
        2
    }
}

impl RangePrf for ConstrainedRCPrfLevel1Element {
    fn range(&self) -> RCPrfRange {
        self.range.clone()
    }

    fn eval(&self, leaf: u64, output: &mut [u8]) -> Result<(), String> {
        if !self.range.contains_leaf(leaf) {
            Err(format!(
                "Evaluation point {} outside of valid range {}",
                leaf, self.range,
            ))
        } else {
            let child = self.get_child_node(
                leaf,
                self.tree_height() - self.subtree_height(),
            );

            println!(
                "Last {}",
                match child {
                    RCPrfTreeNodeChild::LeftChild => "Left (0)",
                    _ => "Right (1)",
                }
            );
            self.prf.fill_bytes(&[child as u8], output);
            Ok(())
        }
    }

    fn eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        if !self.range.contains_range(range) {
            Err(
                format!(
                "Invalid evaluation range: {} is not contained in the valid range {}",
                range, self.range,
            )
            )
        } else if outputs.len() != 2 {
            Err(format!(
                "Invalid outputs slice length {}. Should be 2",
                outputs.len()
            ))
        } else {
            self.eval(range.min(), &mut outputs[0])?;
            self.eval(range.max(), &mut outputs[1])?;

            Ok(())
        }
    }

    fn constrain(
        &self,
        _range: &RCPrfRange,
    ) -> Result<ConstrainedRCPrf, String> {
        Err("Cannot constrain a leaf element".to_string())
    }
}

impl TreeBasedPrf for ConstrainedRCPrfInnerElement {
    fn tree_height(&self) -> u8 {
        self.rcprf_height
    }
}

impl RCPrfElement for ConstrainedRCPrfInnerElement {
    fn is_leaf(&self) -> bool {
        false
    }

    fn subtree_height(&self) -> u8 {
        self.subtree_height
    }
}

impl RangePrf for ConstrainedRCPrfInnerElement {
    fn range(&self) -> RCPrfRange {
        self.range.clone()
    }

    fn eval(&self, leaf: u64, output: &mut [u8]) -> Result<(), String> {
        if !self.range.contains_leaf(leaf) {
            Err(format!(
                "Evaluation point {} outside of valid range {}",
                leaf, self.range,
            ))
        } else {
            let child = self.get_child_node(
                leaf,
                self.tree_height() - self.subtree_height(),
            );

            let half_width = 1u64 << (self.subtree_height() - 2);
            println!("Half width {}", half_width);
            let submin = self.range.min() + (child as u64) * half_width;
            let submax = submin + half_width;
            let r = RCPrfRange::from(submin..submax);

            debug_assert!(
                self.range().contains_range(&r),
                "{} {}",
                self.range,
                r
            );
            debug_assert_eq!(self.range().width() / 2, half_width);

            let subkey = self.prg.derive_key(child as u32);

            println!(
                "{}",
                match child {
                    RCPrfTreeNodeChild::LeftChild => "Left (0)",
                    _ => "Right (1)",
                }
            );

            if self.subtree_height > 3 {
                let child_node = ConstrainedRCPrfInnerElement {
                    prg: KeyDerivationPrg::from_key(subkey),
                    range: r,
                    subtree_height: self.subtree_height() - 1,
                    rcprf_height: self.rcprf_height,
                };
                child_node.eval(leaf, output)
            } else {
                debug_assert_eq!(self.subtree_height, 3);

                let child_node = ConstrainedRCPrfLevel1Element {
                    prf: Prf::from_key(subkey),
                    range: r,
                    rcprf_height: self.rcprf_height,
                };
                child_node.eval(leaf, output)
            }
        }
    }

    fn eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        todo!()
    }

    fn constrain(
        &self,
        range: &RCPrfRange,
    ) -> Result<ConstrainedRCPrf, String> {
        todo!()
    }
}

impl TreeBasedPrf for RCPrf {
    fn tree_height(&self) -> u8 {
        self.root.rcprf_height
    }
}

impl RangePrf for RCPrf {
    fn range(&self) -> RCPrfRange {
        // RCPrfRange::from(0..=max_leaf_index(self.tree_height()))
        self.root.range()
    }

    fn eval(&self, leaf: u64, output: &mut [u8]) -> Result<(), String> {
        self.root.eval(leaf, output)
    }

    fn eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        self.root.eval_range(range, outputs)
    }

    fn constrain(
        &self,
        range: &RCPrfRange,
    ) -> Result<ConstrainedRCPrf, String> {
        todo!()
    }
}

impl RCPrf {
    /// Returns a new RCPrf based on a tree of height `height`, with a random
    /// root.
    pub fn new(height: u8) -> Self {
        RCPrf {
            root: ConstrainedRCPrfInnerElement {
                prg: KeyDerivationPrg::new(),
                rcprf_height: height,
                range: RCPrfRange::from(0..=max_leaf_index(height)),
                subtree_height: height,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rcprf() -> Result<(), String> {
        let rcprf = RCPrf::new(8);

        let mut output = [0u8; 16];
        rcprf.eval(127, &mut output)
    }
}
