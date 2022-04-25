use crate::private::RcPrfElementPair;
use crate::rcprf::*;
use crate::Prf;

use zeroize::Zeroize;

#[derive(Zeroize)]
#[zeroize(drop)]
pub(crate) struct ConstrainedRcPrfLeafElement {
    pub prf: Prf,
    pub index: u64,
    pub rcprf_height: u8,
}

impl TreeBasedPrf for ConstrainedRcPrfLeafElement {
    fn tree_height(&self) -> u8 {
        self.rcprf_height
    }
}

impl private::RcPrfElement for ConstrainedRcPrfLeafElement {
    fn is_leaf(&self) -> bool {
        true
    }

    fn subtree_height(&self) -> u8 {
        2
    }

    fn split_node(&self) -> RcPrfElementPair {
        panic!("Invalid tree state: trying to split a leaf!");
    }
}

impl private::UncheckedRangePrf for ConstrainedRcPrfLeafElement {
    fn unchecked_eval(&self, x: u64, output: &mut [u8]) {
        debug_assert_eq!(x, self.index);
        self.prf.fill_bytes(&[0u8], output);
    }

    fn unchecked_eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        debug_assert_eq!(range.min(), self.index);
        debug_assert_eq!(range.max(), self.index);
        self.unchecked_eval(range.min(), outputs[0]);
    }

    #[cfg(feature = "rayon")]
    fn unchecked_par_eval_range(
        &self,
        range: &RcPrfRange,
        outputs: &mut [&mut [u8]],
    ) {
        // there is no point in parallelizing here
        self.unchecked_eval_range(range, outputs);
    }

    fn unchecked_constrain(&self, range: &RcPrfRange) -> ConstrainedRcPrf {
        debug_assert_eq!(range.width(), 1);
        debug_assert_eq!(range.max(), self.index);

        // here, we do have to copy the PRF
        // We do so by getting the key and copying it
        ConstrainedRcPrf {
            elements: vec![Box::pin(self.insecure_clone())],
        }
    }
}

impl InsecureClone for ConstrainedRcPrfLeafElement {
    fn insecure_clone(&self) -> Self {
        ConstrainedRcPrfLeafElement {
            prf: self.prf.insecure_clone(),
            rcprf_height: self.rcprf_height,
            index: self.index,
        }
    }
}

impl RangePrf for ConstrainedRcPrfLeafElement {
    fn range(&self) -> RcPrfRange {
        RcPrfRange::new(self.index, self.index)
    }
}

impl SerializableCleartextContent for ConstrainedRcPrfLeafElement {
    fn serialization_content_byte_size(&self) -> usize {
        self.prf.serialization_content_byte_size()
            + std::mem::size_of_val(&self.index)
            + std::mem::size_of_val(&self.rcprf_height)
    }
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        writer.write_all(&self.rcprf_height.to_le_bytes())?;
        writer.write_all(&self.index.to_le_bytes())?;
        self.prf.serialize_content(writer)?;

        Ok(self.serialization_content_byte_size())
    }
}

impl DeserializableCleartextContent for ConstrainedRcPrfLeafElement {
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        let mut h_bytes = [0u8; 1];
        reader.read_exact(&mut h_bytes)?;
        let rcprf_height = u8::from_le_bytes(h_bytes);

        let mut i_bytes = [0u8; 8];
        reader.read_exact(&mut i_bytes)?;
        let index = u64::from_le_bytes(i_bytes);

        Ok(ConstrainedRcPrfLeafElement {
            prf: Prf::deserialize_content(reader)?,
            rcprf_height,
            index,
        })
    }
}
