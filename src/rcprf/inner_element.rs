use crate::rcprf::*;
use crate::Prf;

use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub(in crate::rcprf) struct ConstrainedRCPrfInnerElement {
    pub prg: KeyDerivationPrg<Key256>,
    pub range: RCPrfRange,
    pub subtree_height: u8,
    pub rcprf_height: u8,
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
        // range
        //     .clone()
        //     .range
        //     .zip(outputs)
        //     .try_for_each(|(i, out)| self.unchecked_eval(i, out))
        if self.subtree_height() > 2 {
            let half_width = 1u64 << (self.subtree_height() - 2);
            let mut out_offset = 0usize;

            // use scopes to avoid any mixups between left and right subtrees
            {
                let left_range = RCPrfRange::new(
                    self.range().min(),
                    self.range().min() + half_width - 1,
                );

                match left_range.intersection(range) {
                    None => (),
                    Some(r) => {
                        let subkey = self.prg.derive_key(0);
                        let left_child = ConstrainedRCPrfInnerElement {
                            prg: KeyDerivationPrg::from_key(subkey),
                            range: left_range,
                            subtree_height: self.subtree_height() - 1,
                            rcprf_height: self.rcprf_height,
                        };
                        left_child.eval_range(
                            &r,
                            &mut outputs[0..r.width() as usize],
                        )?;
                        out_offset = r.width() as usize;
                    }
                }
            }

            {
                let right_range = RCPrfRange::new(
                    self.range().min() + half_width,
                    self.range().max(),
                );

                match right_range.intersection(range) {
                    None => (),
                    Some(r) => {
                        let subkey = self.prg.derive_key(1);
                        let right_child = ConstrainedRCPrfInnerElement {
                            prg: KeyDerivationPrg::from_key(subkey),
                            range: right_range,
                            subtree_height: self.subtree_height() - 1,
                            rcprf_height: self.rcprf_height,
                        };
                        right_child.eval_range(
                            &r,
                            &mut outputs
                                [out_offset..out_offset + r.width() as usize],
                        )?;
                    }
                }
            }
        } else {
            // we are getting a leaf
            debug_assert!(range.width() <= 2);

            let mut out_offset = 0usize;
            if range.contains_leaf(self.range().min()) {
                let subkey = self.prg.derive_key(0);

                let child_node = ConstrainedRCPrfLeafElement {
                    prf: Prf::from_key(subkey),
                    index: range.min(),
                    rcprf_height: self.rcprf_height,
                };
                child_node
                    .unchecked_eval(self.range().min(), &mut outputs[0])?;
                out_offset += 1;
            }

            if range.contains_leaf(self.range().max()) {
                let subkey = self.prg.derive_key(1);

                let child_node = ConstrainedRCPrfLeafElement {
                    prf: Prf::from_key(subkey),
                    index: range.max(),
                    rcprf_height: self.rcprf_height,
                };
                child_node.unchecked_eval(
                    self.range().max(),
                    &mut outputs[out_offset],
                )?;
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
        if self.subtree_height() > 2 {
            let half_width = 1u64 << (self.subtree_height() - 2);

            rayon::scope(move |s| {
                let mut current = outputs;

                // use scopes to avoid any mixups between left and right subtrees
                {
                    let left_range = RCPrfRange::new(
                        self.range().min(),
                        self.range().min() + half_width - 1,
                    );

                    match left_range.intersection(range) {
                        None => (),
                        Some(r) => {
                            let r_width = r.width() as usize;
                            let (mut left_slice, right_slice) =
                                current.split_at_mut(r_width);
                            current = right_slice;

                            s.spawn(move |_| {
                                let subkey = self.prg.derive_key(0);
                                let left_child = ConstrainedRCPrfInnerElement {
                                    prg: KeyDerivationPrg::from_key(subkey),
                                    range: left_range,
                                    subtree_height: self.subtree_height() - 1,
                                    rcprf_height: self.rcprf_height,
                                };
                                left_child
                                    .par_eval_range(&r, &mut left_slice)
                                    .unwrap();
                            });
                        }
                    }
                }

                {
                    let right_range = RCPrfRange::new(
                        self.range().min() + half_width,
                        self.range().max(),
                    );

                    match right_range.intersection(range) {
                        None => (),
                        Some(r) => {
                            // it is not necessary to spawn a new task here
                            let subkey = self.prg.derive_key(1);
                            let right_child = ConstrainedRCPrfInnerElement {
                                prg: KeyDerivationPrg::from_key(subkey),
                                range: right_range,
                                subtree_height: self.subtree_height() - 1,
                                rcprf_height: self.rcprf_height,
                            };
                            right_child
                                .par_eval_range(&r, &mut current)
                                .unwrap();
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

                let child_node = ConstrainedRCPrfLeafElement {
                    prf: Prf::from_key(subkey),
                    index: range.min(),
                    rcprf_height: self.rcprf_height,
                };
                child_node
                    .unchecked_eval(self.range().min(), &mut outputs[0])?;
                out_offset += 1;
            }

            if range.contains_leaf(self.range().max()) {
                let subkey = self.prg.derive_key(1);

                let child_node = ConstrainedRCPrfLeafElement {
                    prf: Prf::from_key(subkey),
                    index: range.max(),
                    rcprf_height: self.rcprf_height,
                };
                child_node.unchecked_eval(
                    self.range().max(),
                    &mut outputs[out_offset],
                )?;
            }
        }
        Ok(())
    }

    fn unchecked_constrain(
        &self,
        range: &RCPrfRange,
    ) -> Result<ConstrainedRCPrf, String> {
        debug_assert!(self.range().contains_range(range));

        if self.range() == *range {
            return Ok(ConstrainedRCPrf {
                elements: vec![Box::pin(self.insecure_clone())],
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
                elements: vec![Box::pin(child_node)],
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
