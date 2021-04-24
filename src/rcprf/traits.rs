use crate::rcprf::*;

pub(crate) mod private {
    use super::*;

    pub trait UncheckedRangePrf {
        fn unchecked_eval(&self, x: u64, output: &mut [u8]);

        fn unchecked_eval_range(
            &self,
            range: &RcPrfRange,
            outputs: &mut [&mut [u8]],
        );

        fn unchecked_constrain(
            &self,
            range: &RcPrfRange,
        ) -> Result<ConstrainedRcPrf, String>;

        #[cfg(feature = "rayon")]
        fn unchecked_par_eval_range(
            &self,
            range: &RcPrfRange,
            outputs: &mut [&mut [u8]],
        );
    }

    pub(crate) type RcPrfElementPair = (
        Pin<Box<dyn private::RcPrfElement>>,
        Pin<Box<dyn private::RcPrfElement>>,
    );

    pub(crate) trait RcPrfElement:
        TreeBasedPrf + RangePrf + Send + Sync + Zeroize + SerializableCleartext
    {
        fn is_leaf(&self) -> bool;
        fn subtree_height(&self) -> u8;

        fn get_child_node(
            &self,
            leaf: u64,
            node_depth: u8,
        ) -> RcPrfTreeNodeChild {
            get_child_node(self.tree_height(), leaf, node_depth)
        }

        fn split_node(&self) -> RcPrfElementPair;
    }
}

/// Trait representing a PRF that can be evaluated on an integral range
pub trait RangePrf: private::UncheckedRangePrf {
    /// Returns the range on which the PRF can be evaluated
    fn range(&self) -> RcPrfRange;

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
            self.unchecked_eval(x, output);
            Ok(())
        }
    }

    /// Evaluate the PRF on every value of the `range` and put the result in
    /// `outputs` such that the i-th value of the range is put at the i-th
    /// position of the output.
    /// Returns an error when `range` is not contained in the PRF's range.
    fn eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        if !self.range().contains_range(range) {
            Err(format!(
                "Invalid evaluation range: {} is not contained in the valid range {}",
                range,
                self.range(),
            ))
        } else if range.width() != outputs.len() as u64 {
            Err(format!(
                "Incompatible range width ({}) and outputs length ({}).",
                range.width(),
                outputs.len()
            ))
        } else {
            self.unchecked_eval_range(range, outputs);
            Ok(())
        }
    }

    /// Evaluate the PRF on every value of the `range` in parallel and put the
    /// result in `outputs` such that the i-th value of the range is put at the
    /// i-th position of the output.
    /// Returns an error when `range` is not contained in the PRF's range.
    #[cfg(feature = "rayon")]
    fn par_eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) -> Result<(), String> {
        if !self.range().contains_range(range) {
            Err(format!(
                "Invalid evaluation range: {} is not contained in the valid range {}",
                range,
                self.range(),
            ))
        } else if range.width() != outputs.len() as u64 {
            Err(format!(
                "Incompatible range width ({}) and outputs length ({}).",
                range.width(),
                outputs.len()
            ))
        } else {
            self.unchecked_par_eval_range(range, outputs);
            Ok(())
        }
    }

    /// Constrain the PRF on `range`.
    /// Returns an error if `range` does not intersect the PRF's range
    fn constrain(
        &self,
        range: &RcPrfRange,
    ) -> Result<ConstrainedRcPrf, String> {
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
