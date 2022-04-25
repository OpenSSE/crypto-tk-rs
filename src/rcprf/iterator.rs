use crate::rcprf::*;
use std::collections::VecDeque;

/// The output generator (as an iterator) for [`RcPrf`]
pub struct RcPrfIterator {
    pub(crate) node_queue: VecDeque<Pin<Box<dyn private::RcPrfElement>>>,
    pub(crate) output_size: usize,
}

impl Iterator for RcPrfIterator {
    type Item = (u64, Vec<u8>);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(mut elt) = self.node_queue.pop_front() {
            loop {
                if elt.is_leaf() {
                    let mut result = vec![0u8; self.output_size];
                    let x = elt.range().min();
                    // we can use `unchecked_eval` here because we know the
                    // function will not panic as `x` is the minimum value of
                    // the element's range (and hence in the range)
                    elt.unchecked_eval(x, &mut result);
                    return Some((x, result));
                }
                // else
                // split the node in two
                let (left, right) = elt.split_node();

                // reinsert the node in the queue
                self.node_queue.push_front(right);

                // and loop
                elt = left;
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

impl DoubleEndedIterator for RcPrfIterator {
    fn next_back(&mut self) -> Option<Self::Item> {
        if let Some(mut elt) = self.node_queue.pop_back() {
            loop {
                if elt.is_leaf() {
                    let mut result = vec![0u8; self.output_size];

                    let x = elt.range().max();
                    // we can use `unchecked_eval` here because we know the
                    // function will not panic as `x` is the maximum value of
                    // the element's range (and hence in the range)
                    elt.unchecked_eval(x, &mut result);
                    return Some((x, result));
                }
                // else
                // split the node in two
                let (left, right) = elt.split_node();

                // reinsert the node in the queue
                self.node_queue.push_back(left);
                // and loop
                elt = right;
            }
        } else {
            None
        }
    }
}

impl ExactSizeIterator for RcPrfIterator {}

/// Iterator for key-derivation range-constrained PRF
pub struct KeyDerivationRcPrfIterator<KeyType: Key> {
    pub(crate) inner: RcPrfIterator,
    pub(crate) _marker: std::marker::PhantomData<KeyType>,
}

impl<KeyType: Key> Iterator for KeyDerivationRcPrfIterator<KeyType> {
    type Item = (u64, KeyType);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(i, mut buf)| (i, KeyType::from_slice(buf.as_mut())))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<KeyType: Key> DoubleEndedIterator for KeyDerivationRcPrfIterator<KeyType> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.inner
            .next_back()
            .map(|(i, mut buf)| (i, KeyType::from_slice(buf.as_mut())))
    }
}

impl<KeyType: Key> ExactSizeIterator for KeyDerivationRcPrfIterator<KeyType> {}

/// Parallel iterator for [`RcPrf`]s
#[cfg(feature = "rayon")]
pub struct RcPrfParallelIterator {
    base: RcPrfIterator,
}

#[cfg(feature = "rayon")]
impl RcPrfParallelIterator {
    /// Create a new parallel iterator for [`RcPrf`]s from a regular one
    #[must_use]
    pub fn new(base: RcPrfIterator) -> Self {
        RcPrfParallelIterator { base }
    }
}

/// Parallel iterator for [`RcPrf`]s meant for key derivations
#[cfg(feature = "rayon")]
pub struct KeyDerivationRcPrfParallelIterator<KeyType: Key> {
    pub(crate) inner: RcPrfParallelIterator,
    pub(crate) _marker: std::marker::PhantomData<KeyType>,
}

#[cfg(feature = "rayon")]
impl<KeyType: Key> KeyDerivationRcPrfParallelIterator<KeyType> {
    /// Create a new parallel iterator for [`RcPrf`]s from a regular one
    #[must_use]
    pub fn new(inner: RcPrfParallelIterator) -> Self {
        KeyDerivationRcPrfParallelIterator::<KeyType> {
            inner,
            _marker: std::marker::PhantomData,
        }
    }
}

/// Parallel iteration for [`RcPrf`]s
pub mod parallel_iterator {
    use super::*;
    use rayon::iter::plumbing::*;
    use rayon::iter::{IndexedParallelIterator, ParallelIterator};

    impl ParallelIterator for RcPrfParallelIterator {
        type Item = <RcPrfIterator as Iterator>::Item;

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
    impl IndexedParallelIterator for RcPrfParallelIterator {
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

    impl Producer for RcPrfIterator {
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
                VecDeque::<Pin<Box<dyn private::RcPrfElement>>>::with_capacity(
                    capacity,
                );
            let mut right_deque =
                VecDeque::<Pin<Box<dyn private::RcPrfElement>>>::with_capacity(
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
                        .constrain(&RcPrfRange::from(elt.range().min()..leaf))
                        .unwrap();
                    let right_subtree = elt
                        .constrain(&RcPrfRange::from(leaf..=elt.range().max()))
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
                RcPrfIterator {
                    node_queue: left_deque,
                    output_size: self.output_size,
                },
                RcPrfIterator {
                    node_queue: right_deque,
                    output_size: self.output_size,
                },
            )
        }
    }

    impl<KeyType: Key + Send> ParallelIterator
        for KeyDerivationRcPrfParallelIterator<KeyType>
    {
        type Item = <KeyDerivationRcPrfIterator<KeyType> as Iterator>::Item;

        fn drive_unindexed<C>(self, consumer: C) -> C::Result
        where
            C: UnindexedConsumer<Self::Item>,
        {
            bridge(self, consumer)
        }

        fn opt_len(&self) -> Option<usize> {
            // Some(std::iter::ExactSizeIterator::len(self))
            Some(self.inner.len())
        }
    }
    impl<KeyType: Key + Send> IndexedParallelIterator
        for KeyDerivationRcPrfParallelIterator<KeyType>
    {
        fn len(&self) -> usize {
            // <Self as ExactSizeIterator>::len(self)
            self.inner.len()
        }

        fn drive<C: Consumer<Self::Item>>(self, consumer: C) -> C::Result {
            bridge(self, consumer)
        }

        fn with_producer<CB: ProducerCallback<Self::Item>>(
            self,
            callback: CB,
        ) -> CB::Output {
            callback.callback(KeyDerivationRcPrfIterator::<KeyType> {
                inner: self.inner.base,
                _marker: std::marker::PhantomData,
            })
        }
    }

    impl<KeyType: Key + Send> Producer for KeyDerivationRcPrfIterator<KeyType> {
        type Item = <Self as Iterator>::Item;
        type IntoIter = Self;

        fn into_iter(self) -> Self::IntoIter {
            self
        }

        fn split_at(self, index: usize) -> (Self, Self) {
            let (left, right) = self.inner.split_at(index);
            (
                KeyDerivationRcPrfIterator::<KeyType> {
                    inner: left,
                    _marker: std::marker::PhantomData,
                },
                KeyDerivationRcPrfIterator::<KeyType> {
                    inner: right,
                    _marker: std::marker::PhantomData,
                },
            )
        }
    }
}
