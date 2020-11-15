use crate::rcprf::*;
use std::collections::VecDeque;

/// The output generator (as an iterator) for RCPRF
pub struct RCPrfIterator {
    pub(crate) node_queue: VecDeque<Pin<Box<dyn private::RCPrfElement>>>,
    pub(crate) output_size: usize,
}

impl Iterator for RCPrfIterator {
    type Item = (u64, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut elt) = self.node_queue.pop_front() {
            loop {
                if elt.is_leaf() {
                    let mut result = vec![0u8; self.output_size];
                    let x = elt.range().min();
                    elt.eval(x, &mut result).unwrap();
                    return Some((x, result));
                } else {
                    // split the node in two
                    let (left, right) = elt.split_node();

                    // reinsert the node in the queue
                    self.node_queue.push_front(right);

                    // and loop
                    elt = left;
                }
            }
        } else {
            None
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        if self.node_queue.is_empty() {
            (0, Some(0))
        } else {
            let s = (self.node_queue.back().unwrap().range().max()
                - self.node_queue.front().unwrap().range().min()
                + 1) as usize;
            (s, Some(s))
        }
    }
}

impl DoubleEndedIterator for RCPrfIterator {
    fn next_back(&mut self) -> Option<Self::Item> {
        if let Some(mut elt) = self.node_queue.pop_back() {
            loop {
                if elt.is_leaf() {
                    let mut result = vec![0u8; self.output_size];

                    let x = elt.range().max();
                    elt.eval(x, &mut result).unwrap();
                    return Some((x, result));
                } else {
                    // split the node in two
                    let (left, right) = elt.split_node();

                    // reinsert the node in the queue
                    self.node_queue.push_back(left);
                    // and loop
                    elt = right;
                }
            }
        } else {
            None
        }
    }
}

impl ExactSizeIterator for RCPrfIterator {}

/// Parallel iterator for RCPRFs
#[cfg(feature = "rayon")]
pub struct RCPrfParallelIterator {
    base: RCPrfIterator,
}

impl RCPrfParallelIterator {
    pub fn new(base: RCPrfIterator) -> Self {
        RCPrfParallelIterator { base }
    }
}

/// Parallel iteration for RCPRFs
pub mod parallel_iterator {
    use super::*;
    use rayon::iter::plumbing::*;
    use rayon::iter::{IndexedParallelIterator, ParallelIterator};

    impl ParallelIterator for RCPrfParallelIterator {
        type Item = <RCPrfIterator as Iterator>::Item;

        fn drive_unindexed<C>(self, consumer: C) -> C::Result
        where
            C: UnindexedConsumer<Self::Item>,
        {
            bridge(self, consumer)
        }

        fn opt_len(&self) -> Option<usize> {
            // Some(std::iter::ExactSizeIterator::len(self))
            Some(self.base.len())
        }
    }
    impl IndexedParallelIterator for RCPrfParallelIterator {
        fn len(&self) -> usize {
            // <Self as ExactSizeIterator>::len(self)
            self.base.len()
        }

        fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
            bridge(self, consumer)
        }

        fn with_producer<CB: ProducerCallback<Self::Item>>(
            self,
            callback: CB,
        ) -> CB::Output {
            callback.callback(self.base)
        }
    }

    impl Producer for RCPrfIterator {
        type Item = <Self as Iterator>::Item;
        type IntoIter = Self;

        fn into_iter(self) -> Self::IntoIter {
            self
        }

        fn split_at(self, index: usize) -> (Self, Self) {
            // index must be in the right element of the pair
            let capacity =
                self.node_queue.front().unwrap().tree_height() as usize;
            let mut left_deque =
                VecDeque::<Pin<Box<dyn private::RCPrfElement>>>::with_capacity(
                    capacity,
                );
            let mut right_deque =
                VecDeque::<Pin<Box<dyn private::RCPrfElement>>>::with_capacity(
                    capacity,
                );

            let start_index = self.node_queue.front().unwrap().range().min();
            let leaf = start_index + index as u64; // do not forget the offset

            self.node_queue.into_iter().for_each(|elt| {
                if elt.range().max() < leaf {
                    left_deque.push_back(elt);
                } else if elt.range().contains_leaf(leaf)
                    && elt.range().min() != leaf
                // if min == leaf, we need to step into the next case
                {
                    // this is not super efficient as we compute some node
                    // twice (the nodes of the path from the root to leaf)
                    // Yet, this is elegant and the asymptotic complexity is
                    // not affected.
                    let left_subtree = elt
                        .constrain(&RCPrfRange::from(elt.range().min()..leaf))
                        .unwrap();
                    let right_subtree = elt
                        .constrain(&RCPrfRange::from(leaf..=elt.range().max()))
                        .unwrap();

                    left_subtree
                        .elements
                        .into_iter()
                        .for_each(|e| left_deque.push_back(e));
                    right_subtree
                        .elements
                        .into_iter()
                        .for_each(|e| right_deque.push_back(e));
                } else {
                    debug_assert!(elt.range().min() >= leaf);
                    right_deque.push_back(elt);
                }
            });

            (
                RCPrfIterator {
                    node_queue: left_deque,
                    output_size: self.output_size,
                },
                RCPrfIterator {
                    node_queue: right_deque,
                    output_size: self.output_size,
                },
            )
        }
    }
}
