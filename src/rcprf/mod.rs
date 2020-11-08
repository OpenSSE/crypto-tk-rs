//! Range-constrained PRF

use crate::insecure_clone::private::InsecureClone;
use crate::key::Key256;
use crate::prg::KeyDerivationPrg;
use crate::Prf;

// use clear_on_drop::clear::Clear;
// use zeroize::Zeroize;

/// Range structure and functions for use with RCPRFs.
pub mod rcprf_range;

pub use crate::rcprf_range::RCPrfRange;

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

fn get_child_node(
    height: u8,
    leaf_index: u64,
    node_depth: u8,
) -> RCPrfTreeNodeChild {
    debug_assert!(height >= node_depth + 2);
    // the -2 term comes from two facts:
    // - the minimum valid tree height is 1 (single node)
    // - the maximum depth of a node is tree_height-1
    let mask = 1u64 << (height - node_depth - 2);

    if (leaf_index & mask) == 0 {
        RCPrfTreeNodeChild::LeftChild
    } else {
        RCPrfTreeNodeChild::RightChild
    }
}

struct ConstrainedRCPrfInnerElement {
    prg: KeyDerivationPrg<Key256>,
    range: RCPrfRange,
    subtree_height: u8,
    rcprf_height: u8,
}

struct ConstrainedRCPrfLeafElement {
    prf: Prf,
    index: u64,
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

mod private {
    use super::*;
    pub trait UncheckedRangePrf {
        fn unchecked_eval(
            &self,
            x: u64,
            output: &mut [u8],
        ) -> Result<(), String>;

        fn unchecked_eval_range(
            &self,
            range: &RCPrfRange,
            outputs: &mut [&mut [u8]],
        ) -> Result<(), String>;

        fn unchecked_constrain(
            &self,
            range: &RCPrfRange,
        ) -> Result<ConstrainedRCPrf, String>;
    }
}

/// Trait representing a PRF that can be evaluated on an integral range
pub trait RangePrf: private::UncheckedRangePrf {
    /// Returns the range on which the PRF can be evaluated
    fn range(&self) -> RCPrfRange;

    /// Evaluate the PRF on the input `x` and put the result in `output`.
    /// Returns an error when the input is out of the PRF range.
    fn eval(&self, x: u64, output: &mut [u8]) -> Result<(), String> {
        if !self.range().contains_leaf(x) {
            Err(format!(
                "Evaluation point {} outside of valid range {}",
                x,
                self.range(),
            ))
        } else {
            self.unchecked_eval(x, output)
        }
    }

    /// Evaluate the PRF on every value of the `range` and put the result in
    /// `outputs` such that the i-th value of the range is put at the i-th
    /// position of the output.
    /// Returns an error when `range` is not contained in the PRF's range.
    fn eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        if !self.range().contains_range(range) {
            Err(format!(
                "Invalid evaluation range: {} is not contained in the valid range {}",
                range,
                self.range(),
            ))
        } else if range.width() != outputs.len() as u64 {
            return Err(format!(
                "Incompatible range width ({}) and outputs length ({}).",
                range.width(),
                outputs.len()
            ));
        } else {
            self.unchecked_eval_range(range, outputs)
        }
    }

    /// Constrain the PRF on `range`.
    /// Returns an error if `range` does not intersect the PRF's range
    fn constrain(
        &self,
        range: &RCPrfRange,
    ) -> Result<ConstrainedRCPrf, String> {
        if !self.range().contains_range(range) {
            Err(format!(
                "Invalid constrain range: {} is not contained in the valid range {}",
                range,
                self.range(),
            ))
        } else {
            self.unchecked_constrain(range)
        }
    }
}

/// Trait representing a PRF built on a tree structure
pub trait TreeBasedPrf {
    /// Returns the height of the underlying tree of the PRF.
    /// For range constrained PRFs, this stays the same when constraining the
    /// PRF.
    fn tree_height(&self) -> u8;
}

trait RCPrfElement: TreeBasedPrf + RangePrf {
    fn is_leaf(&self) -> bool;
    fn subtree_height(&self) -> u8;

    fn get_child_node(&self, leaf: u64, node_depth: u8) -> RCPrfTreeNodeChild {
        get_child_node(self.tree_height(), leaf, node_depth)
    }
}

impl TreeBasedPrf for ConstrainedRCPrfLeafElement {
    fn tree_height(&self) -> u8 {
        self.rcprf_height
    }
}

impl RCPrfElement for ConstrainedRCPrfLeafElement {
    fn is_leaf(&self) -> bool {
        true
    }

    fn subtree_height(&self) -> u8 {
        2
    }
}

impl private::UncheckedRangePrf for ConstrainedRCPrfLeafElement {
    fn unchecked_eval(&self, x: u64, output: &mut [u8]) -> Result<(), String> {
        debug_assert_eq!(x, self.index);
        self.prf.fill_bytes(&[0u8], output);
        Ok(())
    }

    fn unchecked_eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        debug_assert_eq!(range.min(), self.index);
        debug_assert_eq!(range.max(), self.index);
        self.eval(range.min(), &mut outputs[0])
    }

    fn unchecked_constrain(
        &self,
        range: &RCPrfRange,
    ) -> Result<ConstrainedRCPrf, String> {
        debug_assert_eq!(range.width(), 1);
        debug_assert_eq!(range.max(), self.index);

        // here, we do have to copy the PRF
        // We do so by getting the key and copying it
        Ok(ConstrainedRCPrf {
            elements: vec![Box::new(self.insecure_clone())],
        })
    }
}

impl InsecureClone for ConstrainedRCPrfLeafElement {
    fn insecure_clone(&self) -> Self {
        ConstrainedRCPrfLeafElement {
            prf: self.prf.insecure_clone(),
            rcprf_height: self.rcprf_height,
            index: self.index,
        }
    }
}

impl RangePrf for ConstrainedRCPrfLeafElement {
    fn range(&self) -> RCPrfRange {
        RCPrfRange::new(self.index, self.index)
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

impl private::UncheckedRangePrf for ConstrainedRCPrfInnerElement {
    fn unchecked_eval(
        &self,
        leaf: u64,
        output: &mut [u8],
    ) -> Result<(), String> {
        let child = self
            .get_child_node(leaf, self.tree_height() - self.subtree_height());

        let half_width = 1u64 << (self.subtree_height() - 2);
        let submin = self.range.min() + (child as u64) * half_width;
        let submax = submin + half_width;
        let r = RCPrfRange::from(submin..submax);
        // println!("Subtree height {}", self.subtree_height());
        // println!("Half width {}", half_width);

        debug_assert!(self.range().contains_range(&r), "{} {}", self.range, r);
        debug_assert_eq!(self.range().width() / 2, half_width);

        let subkey = self.prg.derive_key(child as u32);

        // println!(
        //     "{}",
        //     match child {
        //         RCPrfTreeNodeChild::LeftChild => "Left (0)",
        //         _ => "Right (1)",
        //     }
        // );

        if self.subtree_height > 2 {
            let child_node = ConstrainedRCPrfInnerElement {
                prg: KeyDerivationPrg::from_key(subkey),
                range: r,
                subtree_height: self.subtree_height() - 1,
                rcprf_height: self.rcprf_height,
            };
            child_node.eval(leaf, output)
        } else {
            debug_assert_eq!(self.subtree_height, 2);
            debug_assert_eq!(half_width, 1);

            let child_node = ConstrainedRCPrfLeafElement {
                prf: Prf::from_key(subkey),
                index: r.min(),
                rcprf_height: self.rcprf_height,
            };
            child_node.eval(leaf, output)
        }
    }

    fn unchecked_eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        range
            .clone()
            .range
            .zip(outputs)
            .try_for_each(|(i, out)| self.unchecked_eval(i, out))
    }

    fn unchecked_constrain(
        &self,
        range: &RCPrfRange,
    ) -> Result<ConstrainedRCPrf, String> {
        debug_assert!(self.range().contains_range(range));

        if self.range() == *range {
            return Ok(ConstrainedRCPrf {
                elements: vec![Box::new(self.insecure_clone())],
            });
        }

        if self.subtree_height() > 2 {
            let half_width = 1u64 << (self.subtree_height() - 2);
            let left_range = RCPrfRange::new(
                self.range().min(),
                self.range().min() + half_width - 1,
            );
            let right_range = RCPrfRange::new(
                self.range().min() + half_width,
                self.range().max(),
            );

            let left_constrained = match left_range.intersection(range) {
                None => None,
                Some(subrange) => {
                    let subkey = self.prg.derive_key(0);

                    let left_child = ConstrainedRCPrfInnerElement {
                        prg: KeyDerivationPrg::from_key(subkey),
                        range: left_range,
                        subtree_height: self.subtree_height() - 1,
                        rcprf_height: self.rcprf_height,
                    };
                    Some(left_child.unchecked_constrain(&subrange).unwrap())
                }
            };

            let right_constrained = match right_range.intersection(range) {
                None => None,
                Some(subrange) => {
                    let subkey = self.prg.derive_key(1);

                    let right_child = ConstrainedRCPrfInnerElement {
                        prg: KeyDerivationPrg::from_key(subkey),
                        range: right_range,
                        subtree_height: self.subtree_height() - 1,
                        rcprf_height: self.rcprf_height,
                    };
                    Some(right_child.unchecked_constrain(&subrange).unwrap())
                }
            };

            match (left_constrained, right_constrained) {
                (None, None) => Err(format!(
                    "Error when constraining element of range {} on {}. Invalid
                constrain.",
                    self.range(),
                    range
                )),
                (None, Some(constrained_rcprf)) => Ok(constrained_rcprf),
                (Some(constrained_rcprf), None) => Ok(constrained_rcprf),
                (
                    Some(mut constrained_rcprf_left),
                    Some(constrained_rcprf_right),
                ) => {
                    constrained_rcprf_left.merge(constrained_rcprf_right)?;
                    Ok(constrained_rcprf_left)
                }
            }
        } else {
            // we have to return a leaf: the constraining range is not the full
            // range, and we are at height 2
            debug_assert_eq!(range.width(), 1);
            let child = self.get_child_node(
                range.min(),
                self.tree_height() - self.subtree_height(),
            );
            let subkey = self.prg.derive_key(child as u32);

            let child_node = ConstrainedRCPrfLeafElement {
                prf: Prf::from_key(subkey),
                index: range.min(),
                rcprf_height: self.rcprf_height,
            };

            Ok(ConstrainedRCPrf {
                elements: vec![Box::new(child_node)],
            })
        }
    }
}
impl RangePrf for ConstrainedRCPrfInnerElement {
    fn range(&self) -> RCPrfRange {
        self.range.clone()
    }
}

impl InsecureClone for ConstrainedRCPrfInnerElement {
    fn insecure_clone(&self) -> Self {
        ConstrainedRCPrfInnerElement {
            prg: self.prg.insecure_clone(),
            rcprf_height: self.rcprf_height,
            range: self.range.clone(),
            subtree_height: self.subtree_height,
        }
    }
}

impl TreeBasedPrf for RCPrf {
    fn tree_height(&self) -> u8 {
        self.root.rcprf_height
    }
}

impl private::UncheckedRangePrf for RCPrf {
    fn unchecked_eval(
        &self,
        leaf: u64,
        output: &mut [u8],
    ) -> Result<(), String> {
        self.root.unchecked_eval(leaf, output)
    }

    fn unchecked_eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        self.root.unchecked_eval_range(range, outputs)
    }

    fn unchecked_constrain(
        &self,
        range: &RCPrfRange,
    ) -> Result<ConstrainedRCPrf, String> {
        self.root.unchecked_constrain(range)
    }
}
impl RangePrf for RCPrf {
    fn range(&self) -> RCPrfRange {
        self.root.range()
    }
}

impl RCPrf {
    /// Returns a new RCPrf based on a tree of height `height`, with a random
    /// root.
    pub fn new(height: u8) -> Result<Self, String> {
        if height > MAX_HEIGHT {
            return Err(format!(
                "RCPRF height is too large ({}). The maximum height is {}.",
                height, MAX_HEIGHT
            ));
        }
        Ok(RCPrf {
            root: ConstrainedRCPrfInnerElement {
                prg: KeyDerivationPrg::new(),
                rcprf_height: height,
                range: RCPrfRange::from(0..=max_leaf_index(height)),
                subtree_height: height,
            },
        })
    }
}

impl private::UncheckedRangePrf for ConstrainedRCPrf {
    fn unchecked_eval(&self, x: u64, output: &mut [u8]) -> Result<(), String> {
        self.elements
            .iter()
            .find(|elt| elt.range().contains_leaf(x))
            .unwrap()
            .unchecked_eval(x, output)
    }

    fn unchecked_eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        let mut buffer_offset = 0usize;
        for elt in &self.elements {
            match elt.range().intersection(range) {
                Some(r) => {
                    let r_width = r.width();
                    elt.eval_range(
                        &r,
                        &mut outputs
                            [buffer_offset..buffer_offset + r_width as usize],
                    )
                    .unwrap();
                    buffer_offset += r_width as usize;
                }
                None => (),
            }
        }
        Ok(())
    }

    fn unchecked_constrain(
        &self,
        range: &RCPrfRange,
    ) -> Result<ConstrainedRCPrf, String> {
        let mut constrained_rcprf = ConstrainedRCPrf {
            elements: Vec::new(),
        };

        for elt in &self.elements {
            match elt.range().intersection(range) {
                Some(r) => {
                    constrained_rcprf
                        .merge(elt.unchecked_constrain(&r).unwrap())
                        .unwrap();
                }
                None => (),
            }
        }

        Ok(constrained_rcprf)
    }
}
impl TreeBasedPrf for ConstrainedRCPrf {
    fn tree_height(&self) -> u8 {
        debug_assert!(self.elements.len() > 0);
        self.elements[0].tree_height()
    }
}

impl RangePrf for ConstrainedRCPrf {
    fn range(&self) -> RCPrfRange {
        RCPrfRange::new(
            self.elements[0].range().min(),
            self.elements[self.elements.len() - 1].range().min(),
        )
    }
}

impl ConstrainedRCPrf {
    fn merge(
        &mut self,
        mut merged_rcprf: ConstrainedRCPrf,
    ) -> Result<(), String> {
        // only proceed if the ranges are consecutive

        if self.elements.len() == 0 {
            *self = merged_rcprf;
            return Ok(());
        } else if merged_rcprf.elements.len() == 0 {
            return Ok(());
        } else if self.range().max() < merged_rcprf.range().min() {
            if merged_rcprf.range().min() - self.range().max() == 1 {
                // we must append the elements of merged_rcprf to ours
                self.elements.append(&mut merged_rcprf.elements);
                return Ok(());
            }
        } else if self.range().min() > merged_rcprf.range().max() {
            if self.range().min() - merged_rcprf.range().max() == 1 {
                // we must prepend the elements of merged_rcprf to ours
                merged_rcprf.elements.append(&mut self.elements);
                self.elements = merged_rcprf.elements;
                return Ok(());
            }
        }
        Err(format!(
            "Ranges of the RCPRFs to be merged are not consecutive: {} and {}",
            self.range(),
            merged_rcprf.range()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_choice() {
        let height = 10;

        for leaf in 0..=max_leaf_index(height) {
            let mut acc = 0u64;
            for d in 0..height - 1 {
                let child = get_child_node(height, leaf, d);
                acc = (acc << 1) | (child as u64);
            }
            assert_eq!(leaf, acc);
        }
    }

    #[test]
    fn rcprf_range_consistency() {
        let h = 6u8;

        let rcprf = RCPrf::new(h).unwrap();

        let direct_eval: Vec<[u8; 16]> = (0..=max_leaf_index(h))
            .map(|x| {
                let mut out = [0u8; 16];

                rcprf.eval(x, &mut out).unwrap();
                out
            })
            .collect();

        let mut outs = vec![[0u8; 16]; max_leaf_index(h) as usize + 1];
        let mut slice: Vec<&mut [u8]> =
            outs.iter_mut().map(|x| &mut x[..]).collect();

        // iterate over all the possible ranges
        for start in 0..=max_leaf_index(h) {
            for end in start..=max_leaf_index(h) {
                let range_width = (end - start + 1) as usize;
                rcprf
                    .eval_range(
                        &RCPrfRange::from(start..=end),
                        &mut slice[0..range_width],
                    )
                    .unwrap();

                let couple = direct_eval
                    .iter()
                    .skip(start as usize)
                    .take(range_width)
                    .zip(slice.iter());
                couple.for_each(|(x, y)| assert_eq!(x, y));
            }
        }
    }

    #[test]
    fn rcprf_constrain_consistency() {
        let h = 6u8;

        let rcprf = RCPrf::new(h).unwrap();

        let direct_eval: Vec<[u8; 16]> = (0..=max_leaf_index(h))
            .map(|x| {
                let mut out = [0u8; 16];

                rcprf.eval(x, &mut out).unwrap();
                out
            })
            .collect();

        // iterate over all the possible ranges
        for start in 0..=max_leaf_index(h) {
            for end in start..=max_leaf_index(h) {
                let range_width = (end - start + 1) as usize;
                let constrained_rcprf =
                    rcprf.constrain(&RCPrfRange::new(start, end)).unwrap();

                let constrained_eval: Vec<[u8; 16]> = (start..=end)
                    .map(|x| {
                        let mut out = [0u8; 16];

                        constrained_rcprf.eval(x, &mut out).unwrap();
                        out
                    })
                    .collect();

                let couple = direct_eval
                    .iter()
                    .skip(start as usize)
                    .take(range_width)
                    .zip(constrained_eval.iter());
                couple.for_each(|(x, y)| assert_eq!(x, y));
            }
        }
    }

    #[test]
    fn rcprf_errors() {
        assert!(!RCPrf::new(MAX_HEIGHT + 1).is_ok());

        let h = 8u8;
        let rcprf = RCPrf::new(h).unwrap();
        let mut output = [0u8; 16];
        assert!(!rcprf.eval(max_leaf_index(h) + 1, &mut output).is_ok());

        const OUT_VEC_SIZE: usize = 8;
        let mut outs = vec![[0u8; 16]; OUT_VEC_SIZE];
        let mut slice: Vec<&mut [u8]> =
            outs.iter_mut().map(|x| &mut x[..]).collect();

        // out of range error
        assert!(!rcprf
            .eval_range(
                &RCPrfRange::from(
                    max_leaf_index(h)
                        ..(max_leaf_index(h) + OUT_VEC_SIZE as u64)
                ),
                &mut slice
            )
            .is_ok());

        // invalid vector size
        assert!(!rcprf
            .eval_range(&RCPrfRange::from(2..3), &mut slice)
            .is_ok());
    }
}
