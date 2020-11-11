//! Range-constrained PRF

use std::pin::Pin;

use crate::insecure_clone::private::InsecureClone;
use crate::key::Key256;
use crate::prg::KeyDerivationPrg;

// use clear_on_drop::clear::Clear;
use zeroize::Zeroize;

/// Range structure and functions for use with RCPRFs.
pub mod rcprf_range;
/// Traits used to describe RCPRFs.
pub mod traits;

/// Nodes of the tree-based RCPRF .
pub(crate) mod inner_element;
/// Leaves of the tree-based RCPRF .
pub(crate) mod leaf_element;

use crate::inner_element::*;
use crate::leaf_element::*;
pub use crate::rcprf_range::*;
use crate::traits::*;

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

/// An *unconstrained* RCPrf object
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct RCPrf {
    root: ConstrainedRCPrfInnerElement,
}

/// A *constrained* RCPrf object (obtained after constraining a RCPrf - constrained or not)
pub struct ConstrainedRCPrf {
    elements: Vec<Pin<Box<dyn RCPrfElement>>>,
}

trait RCPrfElement: TreeBasedPrf + RangePrf + Send + Sync + Zeroize {
    fn is_leaf(&self) -> bool;
    fn subtree_height(&self) -> u8;

    fn get_child_node(&self, leaf: u64, node_depth: u8) -> RCPrfTreeNodeChild {
        get_child_node(self.tree_height(), leaf, node_depth)
    }
}

impl TreeBasedPrf for RCPrf {
    fn tree_height(&self) -> u8 {
        self.root.tree_height()
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

    #[cfg(feature = "rayon")]
    fn unchecked_par_eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        self.root.unchecked_par_eval_range(range, outputs)
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
        let mut current = outputs;
        for elt in &self.elements {
            match elt.range().intersection(range) {
                Some(r) => {
                    let r_width = r.width() as usize;
                    let (mut left_slice, right_slice) =
                        current.split_at_mut(r_width);
                    current = right_slice;
                    elt.eval_range(&r, &mut left_slice).unwrap();
                }
                None => (),
            }
        }
        Ok(())
    }

    #[cfg(feature = "rayon")]
    fn unchecked_par_eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        rayon::scope(move |s| {
            let mut current = outputs;
            for elt in &self.elements {
                match elt.range().intersection(range) {
                    Some(r) => {
                        let r_width = r.width() as usize;
                        let (mut left_slice, right_slice) =
                            current.split_at_mut(r_width);
                        current = right_slice;
                        s.spawn(move |_| {
                            elt.eval_range(&r, &mut left_slice).unwrap();
                        });
                    }
                    None => (),
                }
            }
        });
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
            self.elements[self.elements.len() - 1].range().max(),
        )
    }
}

impl Zeroize for ConstrainedRCPrf {
    fn zeroize(&mut self) {
        // Elements are zeroized on drop
        self.elements.drain(..);
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
        let mut par_outs = vec![[0u8; 16]; max_leaf_index(h) as usize + 1];
        let mut slice: Vec<&mut [u8]> =
            outs.iter_mut().map(|x| &mut x[..]).collect();
        let mut par_slice: Vec<&mut [u8]> =
            par_outs.iter_mut().map(|x| &mut x[..]).collect();

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

                rcprf
                    .par_eval_range(
                        &RCPrfRange::from(start..=end),
                        &mut par_slice[0..range_width],
                    )
                    .unwrap();

                let triplets = direct_eval
                    .iter()
                    .skip(start as usize)
                    .take(range_width)
                    .zip(slice.iter())
                    .zip(par_slice.iter());
                triplets.for_each(|((x, y), z)| {
                    assert_eq!(x, y);
                    assert_eq!(x, z)
                });
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
