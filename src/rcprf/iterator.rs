use crate::rcprf::*;
use std::collections::VecDeque;

/// The output generator (as an iterator) for RCPRF
pub struct RCPrfIterator {
    pub(crate) node_queue: VecDeque<Pin<Box<dyn private::RCPrfElement>>>,
    pub(crate) output_size: usize,
}

impl Iterator for RCPrfIterator {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if let Some(mut elt) = self.node_queue.pop_front() {
            loop {
                if elt.is_leaf() {
                    let mut result = vec![0u8; self.output_size];

                    elt.eval(elt.range().min(), &mut result).unwrap();
                    return Some(result);
                } else {
                    // split the node in two
                    let (left, right) = elt.split_node();

                    // reinsert the node in the queue
                    // TODO: this could probably be improved using a loop. We use a "functional" approach for the moment
                    self.node_queue.push_front(right);
                    // self.node_queue.push_front(left);
                    // and recall next on itself
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
