use crate::private::{RcPrfElement, RcPrfElementPair};
use crate::rcprf::*;
use crate::serialization::errors::CleartextContentDeserializationError;
use crate::Prf;

use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub(crate) struct ConstrainedRcPrfInnerElement {
    pub prg: KeyDerivationPrg<Key256>,
    pub range: RcPrfRange,
    pub subtree_height: u8,
    pub rcprf_height: u8,
}

impl TreeBasedPrf for ConstrainedRcPrfInnerElement {
    fn tree_height(&self) -> u8 {
        self.rcprf_height
    }
}

impl RcPrfElement for ConstrainedRcPrfInnerElement {
    fn is_leaf(&self) -> bool {
        false
    }

    fn subtree_height(&self) -> u8 {
        self.subtree_height
    }

    fn split_node(&self) -> RcPrfElementPair {
        let (subkey_left, subkey_right) = self.prg.derive_key_pair(0);
        if self.subtree_height > 2 {
            let half_width = self.range().width() / 2;
            let range_left = RcPrfRange::from(
                self.range().min()..self.range().min() + half_width,
            );
            let range_right = RcPrfRange::from(
                self.range().min() + half_width..self.range().max(),
            );
            (
                Box::pin(ConstrainedRcPrfInnerElement {
                    prg: KeyDerivationPrg::from_key(subkey_left),
                    range: range_left,
                    subtree_height: self.subtree_height() - 1,
                    rcprf_height: self.rcprf_height,
                }),
                Box::pin(ConstrainedRcPrfInnerElement {
                    prg: KeyDerivationPrg::from_key(subkey_right),
                    range: range_right,
                    subtree_height: self.subtree_height() - 1,
                    rcprf_height: self.rcprf_height,
                }),
            )
        } else {
            debug_assert_eq!(self.subtree_height, 2);

            (
                Box::pin(ConstrainedRcPrfLeafElement {
                    prf: Prf::from_key(subkey_left),
                    index: self.range().min(),
                    rcprf_height: self.rcprf_height,
                }),
                Box::pin(ConstrainedRcPrfLeafElement {
                    prf: Prf::from_key(subkey_right),
                    index: self.range().max(),
                    rcprf_height: self.rcprf_height,
                }),
            )
        }
    }
}

impl private::UncheckedRangePrf for ConstrainedRcPrfInnerElement {
    fn unchecked_eval(&self, leaf: u64, output: &mut [u8]) {
        let child = self
            .get_child_node(leaf, self.tree_height() - self.subtree_height());

        let half_width = 1u64 << (self.subtree_height() - 2);
        let submin = self.range.min() + (child as u64) * half_width;
        let submax = submin + half_width;
        let r = RcPrfRange::from(submin..submax);

        debug_assert!(self.range().contains_range(&r), "{} {}", self.range, r);
        debug_assert_eq!(self.range().width() / 2, half_width);

        let subkey = self.prg.derive_key(child as u32);

        if self.subtree_height > 2 {
            let child_node = ConstrainedRcPrfInnerElement {
                prg: KeyDerivationPrg::from_key(subkey),
                range: r,
                subtree_height: self.subtree_height() - 1,
                rcprf_height: self.rcprf_height,
            };
            child_node.unchecked_eval(leaf, output);
        } else {
            debug_assert_eq!(self.subtree_height, 2);
            debug_assert_eq!(half_width, 1);

            let child_node = ConstrainedRcPrfLeafElement {
                prf: Prf::from_key(subkey),
                index: r.min(),
                rcprf_height: self.rcprf_height,
            };
            child_node.unchecked_eval(leaf, output);
        }
    }

    fn unchecked_eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        if self.subtree_height() > 2 {
            let half_width = 1u64 << (self.subtree_height() - 2);
            let mut out_offset = 0usize;

            // use scopes to avoid any mixups between left and right subtrees
            {
                let left_range = RcPrfRange::new(
                    self.range().min(),
                    self.range().min() + half_width - 1,
                );

                match left_range.intersection(range) {
                    None => (),
                    Some(r) => {
                        let subkey = self.prg.derive_key(0);
                        let left_child = ConstrainedRcPrfInnerElement {
                            prg: KeyDerivationPrg::from_key(subkey),
                            range: left_range,
                            subtree_height: self.subtree_height() - 1,
                            rcprf_height: self.rcprf_height,
                        };
                        left_child.unchecked_eval_range(
                            &r,
                            &mut outputs[0..r.width() as usize],
                        );
                        out_offset = r.width() as usize;
                    }
                }
            }

            {
                let right_range = RcPrfRange::new(
                    self.range().min() + half_width,
                    self.range().max(),
                );

                match right_range.intersection(range) {
                    None => (),
                    Some(r) => {
                        let subkey = self.prg.derive_key(1);
                        let right_child = ConstrainedRcPrfInnerElement {
                            prg: KeyDerivationPrg::from_key(subkey),
                            range: right_range,
                            subtree_height: self.subtree_height() - 1,
                            rcprf_height: self.rcprf_height,
                        };
                        right_child.unchecked_eval_range(
                            &r,
                            &mut outputs
                                [out_offset..out_offset + r.width() as usize],
                        );
                    }
                }
            }
        } else {
            // we are getting a leaf
            debug_assert!(range.width() <= 2);

            let mut out_offset = 0usize;
            if range.contains_leaf(self.range().min()) {
                let subkey = self.prg.derive_key(0);

                let child_node = ConstrainedRcPrfLeafElement {
                    prf: Prf::from_key(subkey),
                    index: range.min(),
                    rcprf_height: self.rcprf_height,
                };
                child_node.unchecked_eval(self.range().min(), outputs[0]);
                out_offset += 1;
            }

            if range.contains_leaf(self.range().max()) {
                let subkey = self.prg.derive_key(1);

                let child_node = ConstrainedRcPrfLeafElement {
                    prf: Prf::from_key(subkey),
                    index: range.max(),
                    rcprf_height: self.rcprf_height,
                };
                child_node
                    .unchecked_eval(self.range().max(), outputs[out_offset]);
            }
        }
    }

    #[cfg(feature = "rayon")]
    fn unchecked_par_eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        if self.subtree_height() > 2 {
            let half_width = 1u64 << (self.subtree_height() - 2);

            rayon::scope(move |s| {
                let mut current = outputs;

                // use scopes to avoid any mixups between left and right
                // subtrees
                {
                    let left_range = RcPrfRange::new(
                        self.range().min(),
                        self.range().min() + half_width - 1,
                    );

                    match left_range.intersection(range) {
                        None => (),
                        Some(r) => {
                            let r_width = r.width() as usize;
                            let (left_slice, right_slice) =
                                current.split_at_mut(r_width);
                            current = right_slice;

                            s.spawn(move |_| {
                                let subkey = self.prg.derive_key(0);
                                let left_child = ConstrainedRcPrfInnerElement {
                                    prg: KeyDerivationPrg::from_key(subkey),
                                    range: left_range,
                                    subtree_height: self.subtree_height() - 1,
                                    rcprf_height: self.rcprf_height,
                                };
                                left_child
                                    .unchecked_par_eval_range(&r, left_slice);
                            });
                        }
                    }
                }

                {
                    let right_range = RcPrfRange::new(
                        self.range().min() + half_width,
                        self.range().max(),
                    );

                    match right_range.intersection(range) {
                        None => (),
                        Some(r) => {
                            // it is not necessary to spawn a new task here
                            let subkey = self.prg.derive_key(1);
                            let right_child = ConstrainedRcPrfInnerElement {
                                prg: KeyDerivationPrg::from_key(subkey),
                                range: right_range,
                                subtree_height: self.subtree_height() - 1,
                                rcprf_height: self.rcprf_height,
                            };
                            right_child.unchecked_par_eval_range(&r, current);
                        }
                    }
                }
            });
        } else {
            // we are getting a leaf
            // do not parallelize this, it is not worth it
            debug_assert!(range.width() <= 2);

            let mut out_offset = 0usize;
            if range.contains_leaf(self.range().min()) {
                let subkey = self.prg.derive_key(0);

                let child_node = ConstrainedRcPrfLeafElement {
                    prf: Prf::from_key(subkey),
                    index: range.min(),
                    rcprf_height: self.rcprf_height,
                };
                child_node.unchecked_eval(self.range().min(), outputs[0]);
                out_offset += 1;
            }

            if range.contains_leaf(self.range().max()) {
                let subkey = self.prg.derive_key(1);

                let child_node = ConstrainedRcPrfLeafElement {
                    prf: Prf::from_key(subkey),
                    index: range.max(),
                    rcprf_height: self.rcprf_height,
                };
                child_node
                    .unchecked_eval(self.range().max(), outputs[out_offset]);
            }
        }
    }

    fn unchecked_constrain(&self, range: &RcPrfRange) -> ConstrainedRcPrf {
        debug_assert!(self.range().contains_range(range));

        if self.range() == *range {
            return ConstrainedRcPrf {
                elements: vec![Box::pin(self.insecure_clone())],
            };
        }

        if self.subtree_height() > 2 {
            let half_width = 1u64 << (self.subtree_height() - 2);
            let left_range = RcPrfRange::new(
                self.range().min(),
                self.range().min() + half_width - 1,
            );
            let right_range = RcPrfRange::new(
                self.range().min() + half_width,
                self.range().max(),
            );

            let left_constrained = match left_range.intersection(range) {
                None => None,
                Some(subrange) => {
                    let subkey = self.prg.derive_key(0);

                    let left_child = ConstrainedRcPrfInnerElement {
                        prg: KeyDerivationPrg::from_key(subkey),
                        range: left_range,
                        subtree_height: self.subtree_height() - 1,
                        rcprf_height: self.rcprf_height,
                    };
                    Some(left_child.unchecked_constrain(&subrange))
                }
            };

            let right_constrained = match right_range.intersection(range) {
                None => None,
                Some(subrange) => {
                    let subkey = self.prg.derive_key(1);

                    let right_child = ConstrainedRcPrfInnerElement {
                        prg: KeyDerivationPrg::from_key(subkey),
                        range: right_range,
                        subtree_height: self.subtree_height() - 1,
                        rcprf_height: self.rcprf_height,
                    };
                    Some(right_child.unchecked_constrain(&subrange))
                }
            };

            match (left_constrained, right_constrained) {
                (None, None) => unreachable!(
                    "Error when constraining element of range {} on {}. Invalid
                constrain.",
                    self.range(),
                    range
                ),
                (None, Some(constrained_rcprf))
                | (Some(constrained_rcprf), None) => constrained_rcprf,
                (
                    Some(mut constrained_rcprf_left),
                    Some(constrained_rcprf_right),
                ) => {
                    // We know that these RC-PRF have consecutive ranges, so no
                    // panic happens here
                    #[allow(clippy::unwrap_used)]
                    constrained_rcprf_left
                        .merge(constrained_rcprf_right)
                        .unwrap();
                    constrained_rcprf_left
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

            let child_node = ConstrainedRcPrfLeafElement {
                prf: Prf::from_key(subkey),
                index: range.min(),
                rcprf_height: self.rcprf_height,
            };

            ConstrainedRcPrf {
                elements: vec![Box::pin(child_node)],
            }
        }
    }
}
impl RangePrf for ConstrainedRcPrfInnerElement {
    fn range(&self) -> RcPrfRange {
        self.range.clone()
    }
}

impl InsecureClone for ConstrainedRcPrfInnerElement {
    fn insecure_clone(&self) -> Self {
        ConstrainedRcPrfInnerElement {
            prg: self.prg.insecure_clone(),
            rcprf_height: self.rcprf_height,
            range: self.range.clone(),
            subtree_height: self.subtree_height,
        }
    }
}

impl SerializableCleartextContent for ConstrainedRcPrfInnerElement {
    fn serialization_content_byte_size(&self) -> usize {
        self.prg.serialization_content_byte_size()
            + std::mem::size_of_val(&self.subtree_height)
            + std::mem::size_of_val(&self.rcprf_height)
            + self.range.serialization_content_byte_size()
    }
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        writer.write_all(&self.rcprf_height.to_le_bytes())?;
        writer.write_all(&self.subtree_height.to_le_bytes())?;
        self.range.serialize_content(writer)?;
        self.prg.serialize_content(writer)?;

        Ok(self.serialization_content_byte_size())
    }
}

impl DeserializableCleartextContent for ConstrainedRcPrfInnerElement {
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        let mut h_bytes = [0u8; 1];
        reader.read_exact(&mut h_bytes)?;
        let rcprf_height = u8::from_le_bytes(h_bytes);

        let mut sub_h_bytes = [0u8; 1];
        reader.read_exact(&mut sub_h_bytes)?;
        let subtree_height = u8::from_le_bytes(sub_h_bytes);

        let range = RcPrfRange::deserialize_content(reader)?;

        Ok(ConstrainedRcPrfInnerElement {
            prg: KeyDerivationPrg::<Key256>::deserialize_content(reader)?,
            rcprf_height,
            subtree_height,
            range,
        })
    }
}
