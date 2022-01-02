//! Range-constrained PRF

use either::Either;
use std::pin::Pin;

use crate::insecure_clone::private::InsecureClone;
use crate::key::Key256;
use crate::prg::KeyDerivationPrg;
use crate::serialization::cleartext_serialization::*;
use crate::serialization::errors::*;
use crate::Key;

// use clear_on_drop::clear::Clear;
use zeroize::Zeroize;

/// Range structure and functions for use with RcPrfs.
pub mod rcprf_range;
/// Traits used to describe RcPrfs.
pub mod traits;

/// Nodes of the tree-based RcPrf.
pub(crate) mod inner_element;
/// Leaves of the tree-based RcPrf.
pub(crate) mod leaf_element;

/// All the generators for the RcPrf
pub mod iterator;

use crate::inner_element::*;
use crate::leaf_element::*;
pub use crate::rcprf_range::*;
pub use crate::traits::*;

/// Range-constrained pseudo-random functions
///
/// ## Concept
///
/// The point of range-constrained pseudo-random functions (RC-PRF) is to have
/// PRFs for which you can restrict the evaluation to a specific range. In
/// practice, you call a `constrain` algorithm on the RC-PRF, with a range
/// argument `(a..b)`, and get a PRF-like object that you can evaluate on
/// integer in the range `[a, b-1]`.
///
/// Our RC-PRF implementation is based on a tree construction, similar to the
/// Goldreich-Goldwasser-Micali construction.

// Type encoding a choice of child in a binary tree.
#[derive(Clone, Copy, Debug)]
pub(crate) enum RcPrfTreeNodeChild {
    LeftChild = 0,
    RightChild = 1,
}

/// Maximum tree height of a RcPrf tree
pub const MAX_HEIGHT: u8 = 65;

/// Returns the maximum leaf index for a RcPrf using a tree of height `height`.
/// It returns 0 for a tree of height 0 and 2^64-1 for a `height` larger or
/// equal to `MAX_HEIGHT` (65)
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
) -> RcPrfTreeNodeChild {
    debug_assert!(height >= node_depth + 2);
    // the -2 term comes from two facts:
    // - the minimum valid tree height is 1 (single node)
    // - the maximum depth of a node is tree_height-1
    let mask = 1u64 << (height - node_depth - 2);

    if (leaf_index & mask) == 0 {
        RcPrfTreeNodeChild::LeftChild
    } else {
        RcPrfTreeNodeChild::RightChild
    }
}

/// An *unconstrained* RcPrf object
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct RcPrf {
    root: ConstrainedRcPrfInnerElement,
}

/// A *constrained* RcPrf object (obtained after constraining a RcPrf -
/// constrained or not)
pub struct ConstrainedRcPrf {
    elements: Vec<Pin<Box<dyn private::RcPrfElement>>>,
}

impl TreeBasedPrf for RcPrf {
    fn tree_height(&self) -> u8 {
        self.root.tree_height()
    }
}

impl private::UncheckedRangePrf for RcPrf {
    fn unchecked_eval(&self, leaf: u64, output: &mut [u8]) {
        self.root.unchecked_eval(leaf, output)
    }

    fn unchecked_eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        self.root.unchecked_eval_range(range, outputs)
    }

    #[cfg(feature = "rayon")]
    fn unchecked_par_eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        self.root.unchecked_par_eval_range(range, outputs)
    }

    fn unchecked_constrain(
        &self,
        range: &RcPrfRange,
    ) -> Result<ConstrainedRcPrf, String> {
        self.root.unchecked_constrain(range)
    }
}
impl RangePrf for RcPrf {
    fn range(&self) -> RcPrfRange {
        self.root.range()
    }
}

impl RcPrf {
    /// Returns a new RcPrf based on a tree of height `height`, with a random
    /// root.
    pub fn new(height: u8) -> Result<Self, String> {
        Self::from_key(Key256::new(), height)
    }

    /// Returns a new RcPrf based on a tree of height `height`, with the given
    /// root key.
    pub fn from_key(root: Key256, height: u8) -> Result<Self, String> {
        if height > MAX_HEIGHT {
            return Err(format!(
                "RcPrf height is too large ({}). The maximum height is {}.",
                height, MAX_HEIGHT
            ));
        }
        Ok(RcPrf {
            root: ConstrainedRcPrfInnerElement {
                prg: KeyDerivationPrg::from_key(root),
                rcprf_height: height,
                range: RcPrfRange::from(0..=max_leaf_index(height)),
                subtree_height: height,
            },
        })
    }

    /// Returns an iterator of (`index`,`value`) pairs such that `value` is the
    /// evaluation of the RcPrf on `index`.
    /// The values generated by this iterator are vectors of `output_width`
    /// bytes
    pub fn index_value_iter_range(
        &self,
        range: &RcPrfRange,
        output_width: usize,
    ) -> Result<iterator::RcPrfIterator, String> {
        let constrained_rcprf = self.constrain(range)?;

        Ok(constrained_rcprf.into_index_value_iter(output_width))
    }

    /// Returns a parallel iterator of (`index`,`value`) pairs such that
    /// `value` is the evaluation of the RcPrf on `index`. This iterator
    /// is to be used with the `rayon` crate.
    /// The values generated by this iterator are vectors of `output_width`
    /// bytes
    #[cfg(feature = "rayon")]
    pub fn index_value_par_iter_range(
        &self,
        range: &RcPrfRange,
        output_width: usize,
    ) -> Result<iterator::RcPrfParallelIterator, String> {
        let constrained_rcprf = self.constrain(range)?;

        Ok(constrained_rcprf.into_index_value_par_iter(output_width))
    }
}

impl private::UncheckedRangePrf for ConstrainedRcPrf {
    fn unchecked_eval(&self, x: u64, output: &mut [u8]) {
        self.elements
            .iter()
            .find(|elt| elt.range().contains_leaf(x))
            .unwrap()
            .unchecked_eval(x, output)
    }

    fn unchecked_eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        let mut current = outputs;
        for elt in &self.elements {
            if let Some(r) = elt.range().intersection(range) {
                let r_width = r.width() as usize;
                let (mut left_slice, right_slice) =
                    current.split_at_mut(r_width);
                current = right_slice;
                elt.eval_range(&r, &mut left_slice).unwrap();
            }
        }
    }

    #[cfg(feature = "rayon")]
    fn unchecked_par_eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        rayon::scope(move |s| {
            let mut current = outputs;
            for elt in &self.elements {
                if let Some(r) = elt.range().intersection(range) {
                    let r_width = r.width() as usize;
                    let (mut left_slice, right_slice) =
                        current.split_at_mut(r_width);
                    current = right_slice;
                    s.spawn(move |_| {
                        elt.par_eval_range(&r, &mut left_slice).unwrap();
                    });
                }
            }
        });
    }

    fn unchecked_constrain(
        &self,
        range: &RcPrfRange,
    ) -> Result<ConstrainedRcPrf, String> {
        let mut constrained_rcprf = ConstrainedRcPrf {
            elements: Vec::new(),
        };

        for elt in &self.elements {
            if let Some(r) = elt.range().intersection(range) {
                constrained_rcprf
                    .merge(elt.unchecked_constrain(&r).unwrap())
                    .unwrap();
            }
        }

        Ok(constrained_rcprf)
    }
}

impl TreeBasedPrf for ConstrainedRcPrf {
    fn tree_height(&self) -> u8 {
        debug_assert!(!self.elements.is_empty());
        self.elements[0].tree_height()
    }
}

impl RangePrf for ConstrainedRcPrf {
    fn range(&self) -> RcPrfRange {
        RcPrfRange::new(
            self.elements[0].range().min(),
            self.elements[self.elements.len() - 1].range().max(),
        )
    }
}

impl Zeroize for ConstrainedRcPrf {
    fn zeroize(&mut self) {
        // Elements are zeroized on drop
        self.elements.drain(..);
    }
}

impl ConstrainedRcPrf {
    fn merge(
        &mut self,
        mut merged_rcprf: ConstrainedRcPrf,
    ) -> Result<(), String> {
        // only proceed if the ranges are consecutive

        if self.elements.is_empty() {
            *self = merged_rcprf;
            return Ok(());
        } else if merged_rcprf.elements.is_empty() {
            return Ok(());
        } else if self.range().max() < merged_rcprf.range().min() {
            if merged_rcprf.range().min() - self.range().max() == 1 {
                // we must append the elements of merged_rcprf to ours
                self.elements.append(&mut merged_rcprf.elements);
                return Ok(());
            }
        } else if self.range().min() > merged_rcprf.range().max()
            && self.range().min() - merged_rcprf.range().max() == 1
        {
            // we must prepend the elements of merged_rcprf to ours
            merged_rcprf.elements.append(&mut self.elements);
            self.elements = merged_rcprf.elements;
            return Ok(());
        }
        Err(format!(
            "Ranges of the RcPrfs to be merged are not consecutive: {} and {}",
            self.range(),
            merged_rcprf.range()
        ))
    }

    /// Transform the constrained RcPrf into an iterator that produces pairs of
    /// index and evaluation value for that index.
    /// Values produced by that iterator are vectors of size `out_size`.
    pub fn into_index_value_iter(
        self,
        out_size: usize,
    ) -> iterator::RcPrfIterator {
        iterator::RcPrfIterator {
            node_queue: self.elements.into_iter().collect(),
            output_size: out_size,
        }
    }

    /// Transform the constrained RcPrf into a parallel iterator that can be
    /// used with the `rayon` crate, and which produces pairs of index and
    /// evaluation value for that index.
    /// Values produced by that iterator are vectors of size `out_size`.
    #[cfg(feature = "rayon")]
    pub fn into_index_value_par_iter(
        self,
        out_size: usize,
    ) -> iterator::RcPrfParallelIterator {
        iterator::RcPrfParallelIterator::new(iterator::RcPrfIterator {
            node_queue: self.elements.into_iter().collect(),
            output_size: out_size,
        })
    }
}

impl SerializableCleartextContent for RcPrf {
    fn serialization_content_byte_size(&self) -> usize {
        self.root.serialization_content_byte_size()
    }
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        self.root.serialize_content(writer)
    }
}

impl DeserializableCleartextContent for RcPrf {
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        Ok(RcPrf {
            root: ConstrainedRcPrfInnerElement::deserialize_content(reader)?,
        })
    }
}

impl SerializableCleartextContent for ConstrainedRcPrf {
    fn serialization_content_byte_size(&self) -> usize {
        std::mem::size_of::<u64>() // encode the number of elements on 64 bits
            + self
                .elements
                .iter()
                .map(|pinned_elt| pinned_elt.cleartext_serialization_length())
                .sum::<usize>()
    }
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        let elt_len_64 = self.elements.len() as u64;
        writer.write_all(&elt_len_64.to_le_bytes())?;
        let written_bytes: usize = self
            .elements
            .iter()
            .map(|elt| elt.serialize_cleartext(writer))
            .sum::<Result<usize, std::io::Error>>()?;
        Ok(written_bytes + std::mem::size_of::<u64>())
    }
}

impl DeserializableCleartextContent for ConstrainedRcPrf {
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        let mut elt_count_bytes = [0u8; 8];
        reader.read_exact(&mut elt_count_bytes)?;
        let elt_count = u64::from_le_bytes(elt_count_bytes);

        let mut elements = vec![];

        type EitherLoc =
            Either<ConstrainedRcPrfLeafElement, ConstrainedRcPrfInnerElement>;

        for i in 0..elt_count {
            let elt: Pin<Box<dyn private::RcPrfElement>> =
                match deserialize_either_cleartext::<
                    ConstrainedRcPrfLeafElement,
                    ConstrainedRcPrfInnerElement,
                >(reader)
                .map_err(|e| {
                    CleartextContentDeserializationError::ContentError(
                        format!("Issue when deserializing the {}-th element of the constrained RCPRF: {}", i, e)
                            ,
                    )
                })? {
                    EitherLoc::Left(leaf) => Box::pin(leaf),
                    EitherLoc::Right(inner) => Box::pin(inner),
                };

            elements.push(elt);
        }

        Ok(ConstrainedRcPrf { elements })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rayon::iter::ParallelIterator;

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

        let rcprf = RcPrf::new(h).unwrap();

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
                        &RcPrfRange::from(start..=end),
                        &mut slice[0..range_width],
                    )
                    .unwrap();

                rcprf
                    .par_eval_range(
                        &RcPrfRange::from(start..=end),
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

        let rcprf = RcPrf::new(h).unwrap();

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
                let range = RcPrfRange::new(start, end);
                let constrained_rcprf = rcprf.constrain(&range).unwrap();

                let constrained_eval: Vec<[u8; 16]> = (start..=end)
                    .map(|x| {
                        let mut out = [0u8; 16];

                        constrained_rcprf.eval(x, &mut out).unwrap();
                        out
                    })
                    .collect();

                let par_eval_res: Vec<(u64, Vec<u8>)> = rcprf
                    .index_value_par_iter_range(&range, 16)
                    .unwrap()
                    .collect();

                let triplets = direct_eval
                    .iter()
                    .skip(start as usize)
                    .take(range_width)
                    .zip(constrained_eval.iter())
                    .zip(rcprf.index_value_iter_range(&range, 16).unwrap())
                    .zip(par_eval_res.into_iter());
                triplets.for_each(|(((x, y), (_, z)), (_, t))| {
                    assert_eq!(x, y);
                    assert_eq!(&x[..], &z[..]);
                    assert_eq!(&x[..], &t[..]);
                });

                let rev_couple = direct_eval
                    .iter()
                    .skip(start as usize)
                    .take(range_width)
                    .rev()
                    .zip(
                        rcprf.index_value_iter_range(&range, 16).unwrap().rev(),
                    );
                rev_couple.for_each(|(x, (_, y))| {
                    assert_eq!(&x[..], &y[..]);
                });
            }
        }
    }

    #[test]
    fn rcprf_errors() {
        assert!(!RcPrf::new(MAX_HEIGHT + 1).is_ok());

        let h = 8u8;
        let rcprf = RcPrf::new(h).unwrap();
        let mut output = [0u8; 16];
        assert!(!rcprf.eval(max_leaf_index(h) + 1, &mut output).is_ok());

        const OUT_VEC_SIZE: usize = 8;
        let mut outs = vec![[0u8; 16]; OUT_VEC_SIZE];
        let mut slice: Vec<&mut [u8]> =
            outs.iter_mut().map(|x| &mut x[..]).collect();

        // out of range error
        assert!(!rcprf
            .eval_range(
                &RcPrfRange::from(
                    max_leaf_index(h)
                        ..(max_leaf_index(h) + OUT_VEC_SIZE as u64)
                ),
                &mut slice
            )
            .is_ok());

        // invalid vector size
        assert!(!rcprf
            .eval_range(&RcPrfRange::from(2..3), &mut slice)
            .is_ok());
    }
}
