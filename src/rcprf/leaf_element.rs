use crate::rcprf::*;
use crate::Prf;

use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub(in crate::rcprf) struct ConstrainedRCPrfLeafElement {
    pub prf: Prf,
    pub index: u64,
    pub rcprf_height: u8,
}

impl TreeBasedPrf for ConstrainedRCPrfLeafElement {
    fn tree_height(&self) -> u8 {
        self.rcprf_height
    }
}

impl private::RCPrfElement for ConstrainedRCPrfLeafElement {
    fn is_leaf(&self) -> bool {
        true
    }

    fn subtree_height(&self) -> u8 {
        2
    }

    fn split_node(
        &self,
    ) -> (
        Pin<Box<dyn private::RCPrfElement>>,
        Pin<Box<dyn private::RCPrfElement>>,
    ) {
        panic!("Invalid tree state: trying to split a leaf!");
    }
}

impl private::UncheckedRangePrf for ConstrainedRCPrfLeafElement {
    fn unchecked_eval(&self, x: u64, output: &mut [u8]) {
        debug_assert_eq!(x, self.index);
        self.prf.fill_bytes(&[0u8], output);
    }

    fn unchecked_eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        debug_assert_eq!(range.min(), self.index);
        debug_assert_eq!(range.max(), self.index);
        self.unchecked_eval(range.min(), &mut outputs[0])
    }

    #[cfg(feature = "rayon")]
    fn unchecked_par_eval_range(
        &self,
        range: &RCPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        // there is no point in parallelizing here
        self.unchecked_eval_range(range, outputs)
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
            elements: vec![Box::pin(self.insecure_clone())],
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
