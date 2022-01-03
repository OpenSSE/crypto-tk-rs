//! RcPrf meant for key derivation

use super::*;

pub(crate) mod key_derivation_private {
    use crate::{Key, RangePrf};

    pub trait InnerRangePrf {
        type KeyType: Key;
        fn inner(&self) -> &dyn RangePrf;
    }
}

/// A wrapper trait for range PRFs that can derive keys
pub trait KeyDerivationRangePrf: key_derivation_private::InnerRangePrf {
    /// Returns the range on which the PRF can be evaluated
    fn range(&self) -> RcPrfRange {
        self.inner().range()
    }

    /// Evaluate the PRF on the input `x` and put the result in `output`.
    /// Returns an error when the input is out of the PRF range.
    fn derive_key(&self, x: u64) -> Result<Self::KeyType, String> {
        let mut buf = vec![0u8; Self::KeyType::KEY_SIZE];
        self.inner().eval(x, &mut buf)?;
        Ok(Self::KeyType::from_slice(buf.as_mut()))
    }

    /// Evaluate the PRF on every value of the `range` and put the result in
    /// `outputs` such that the i-th value of the range is put at the i-th
    /// position of the output.
    /// Returns an error when `range` is not contained in the PRF's range.
    ///
    /// This method is very inefficient in terms of memory. Use an
    /// iterator instead.
    fn derive_keys_range(
        &self,
        range: &RcPrfRange,
    ) -> Result<Vec<Self::KeyType>, String> {
        let l = range.width() as usize;
        let mut key_bufs = vec![vec![0u8; Self::KeyType::KEY_SIZE]; l];
        let mut slices: Vec<&mut [u8]> =
            key_bufs.iter_mut().map(|x| &mut x[..]).collect();
        self.inner().eval_range(range, slices.as_mut())?;

        Ok(key_bufs
            .into_iter()
            .map(|mut b| Self::KeyType::from_slice(b.as_mut()))
            .collect())
    }

    /// Evaluate the PRF on every value of the `range` in parallel and put the
    /// result in `outputs` such that the i-th value of the range is put at the
    /// i-th position of the output.
    /// Returns an error when `range` is not contained in the PRF's range.
    ///
    /// This method is very inefficient in terms of memory. Use a parallel
    /// iterator instead.
    #[cfg(feature = "rayon")]
    fn par_derive_keys_range(
        &self,
        range: &RcPrfRange,
    ) -> Result<Vec<Self::KeyType>, String> {
        let l = range.width() as usize;
        let mut key_bufs = vec![vec![0u8; Self::KeyType::KEY_SIZE]; l];
        let mut slices: Vec<&mut [u8]> =
            key_bufs.iter_mut().map(|x| &mut x[..]).collect();
        self.inner().par_eval_range(range, slices.as_mut())?;

        Ok(key_bufs
            .into_iter()
            .map(|mut b| Self::KeyType::from_slice(b.as_mut()))
            .collect())
    }

    /// Constrain the PRF on `range`.
    /// Returns an error if `range` does not intersect the PRF's range
    fn constrain(
        &self,
        range: &RcPrfRange,
    ) -> Result<KeyDerivationConstrainedRcPrf<Self::KeyType>, String> {
        Ok(KeyDerivationConstrainedRcPrf::<Self::KeyType> {
            inner: self.inner().constrain(range)?,
            _marker: std::marker::PhantomData,
        })
    }
}

impl<T: key_derivation_private::InnerRangePrf> KeyDerivationRangePrf for T {}

/// An RcPrf generating keys instead of bytes slices
pub struct KeyDerivationRcPrf<KeyType: Key> {
    inner: RcPrf,
    _marker: std::marker::PhantomData<KeyType>,
}

impl<KeyType: Key> Zeroize for KeyDerivationRcPrf<KeyType> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<KeyType: Key> key_derivation_private::InnerRangePrf
    for KeyDerivationRcPrf<KeyType>
{
    type KeyType = KeyType;

    fn inner(&self) -> &dyn RangePrf {
        &self.inner
    }
}

impl<KeyType: Key> KeyDerivationRcPrf<KeyType> {
    /// Returns a new RcPrf based on a tree of height `height`, with a random
    /// root.
    pub fn new(height: u8) -> Result<Self, String> {
        Self::from_key(Key256::new(), height)
    }

    /// Returns a new RcPrf based on a tree of height `height`, with the given
    /// root key.
    pub fn from_key(root: Key256, height: u8) -> Result<Self, String> {
        Ok(KeyDerivationRcPrf::<KeyType> {
            inner: RcPrf::from_key(root, height)?,
            _marker: std::marker::PhantomData,
        })
    }

    /// Returns an iterator of (`index`,`key`) pairs such that `key` is the
    /// key derived from `index` by the RcPrf on `index`.
    pub fn key_range_iter(
        &self,
        range: &RcPrfRange,
    ) -> Result<iterator::KeyDerivationRcPrfIterator<KeyType>, String> {
        let constrained_rcprf = self.constrain(range)?;
        Ok(constrained_rcprf.into_key_iter())
    }

    /// Returns a parallel iterator of (`index`,`key`) pairs such that
    /// `key` is the key derived from `index` by the RcPrf on `index`. This
    /// iterator is to be used with the `rayon` crate.
    #[cfg(feature = "rayon")]
    pub fn key_range_par_iter(
        &self,
        range: &RcPrfRange,
    ) -> Result<iterator::KeyDerivationRcPrfParallelIterator<KeyType>, String>
    {
        let constrained_rcprf = self.constrain(range)?;
        Ok(constrained_rcprf.into_key_par_iter())
    }
}

/// A Constrained RcPrf generating keys instead of bytes slices
pub struct KeyDerivationConstrainedRcPrf<KeyType: Key> {
    inner: ConstrainedRcPrf,
    _marker: std::marker::PhantomData<KeyType>,
}

impl<KeyType: Key> Zeroize for KeyDerivationConstrainedRcPrf<KeyType> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<KeyType: Key> key_derivation_private::InnerRangePrf
    for KeyDerivationConstrainedRcPrf<KeyType>
{
    type KeyType = KeyType;

    fn inner(&self) -> &dyn RangePrf {
        &self.inner
    }
}

impl<KeyType: Key> KeyDerivationConstrainedRcPrf<KeyType> {
    fn into_inner(self) -> ConstrainedRcPrf {
        self.inner
    }
    /// Transform the constrained RcPrf into an iterator that produces pairs of
    /// index and keys derived from that index.
    pub fn into_key_iter(
        self,
    ) -> iterator::KeyDerivationRcPrfIterator<KeyType> {
        let inner_rcprf = self.into_inner();
        let inner = inner_rcprf.into_value_iter(KeyType::KEY_SIZE);
        iterator::KeyDerivationRcPrfIterator::<KeyType> {
            inner,
            _marker: std::marker::PhantomData,
        }
    }

    /// Transform the constrained RcPrf into a parallel iterator that can be
    /// used with the `rayon` crate, and which produces pairs of index and
    /// keys derived from that index.
    #[cfg(feature = "rayon")]
    pub fn into_key_par_iter(
        self,
    ) -> iterator::KeyDerivationRcPrfParallelIterator<KeyType> {
        iterator::KeyDerivationRcPrfParallelIterator::<KeyType> {
            inner: self.into_inner().into_value_par_iter(KeyType::KEY_SIZE),
            _marker: std::marker::PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KeyAccessor;
    use rayon::iter::ParallelIterator;

    #[test]
    fn key_derivation_rcprf_consistency() {
        let h = 6u8;
        let k = Key256::new();
        let k_dup = k.insecure_clone();

        let rcprf = RcPrf::from_key(k, h).unwrap();
        let key_derivation =
            KeyDerivationRcPrf::<Key256>::from_key(k_dup, h).unwrap();

        let mut reference =
            vec![[0u8; Key256::KEY_SIZE]; max_leaf_index(h) as usize + 1];
        let mut slice: Vec<&mut [u8]> =
            reference.iter_mut().map(|x| &mut x[..]).collect();
        rcprf
            .eval_range(
                &RcPrfRange::from(0..=max_leaf_index(h)),
                slice.as_mut(),
            )
            .unwrap();

        let iter_keys = key_derivation
            .key_range_iter(&RcPrfRange::from(0..=max_leaf_index(h)))
            .unwrap();

        let keys = key_derivation
            .derive_keys_range(&RcPrfRange::from(0..=max_leaf_index(h)))
            .unwrap();

        keys.into_iter().zip(iter_keys).zip(reference).for_each(
            |((k, (_i, k_iter)), reference)| {
                assert_eq!(k.content(), reference);
                assert_eq!(k_iter.content(), reference);
            },
        );
    }

    #[test]
    fn par_key_derivation_rcprf_consistency() {
        let h = 6u8;
        let k = Key256::new();
        let k_dup = k.insecure_clone();

        let rcprf = RcPrf::from_key(k, h).unwrap();
        let key_derivation =
            KeyDerivationRcPrf::<Key256>::from_key(k_dup, h).unwrap();

        let mut reference =
            vec![[0u8; Key256::KEY_SIZE]; max_leaf_index(h) as usize + 1];
        let mut slice: Vec<&mut [u8]> =
            reference.iter_mut().map(|x| &mut x[..]).collect();
        rcprf
            .par_eval_range(
                &RcPrfRange::from(0..=max_leaf_index(h)),
                slice.as_mut(),
            )
            .unwrap();

        let keys = key_derivation
            .par_derive_keys_range(&RcPrfRange::from(0..=max_leaf_index(h)))
            .unwrap();

        let par_iter_keys: Vec<(u64, Key256)> = key_derivation
            .key_range_par_iter(&RcPrfRange::from(0..=max_leaf_index(h)))
            .unwrap()
            .collect();

        keys.into_iter()
            .zip(par_iter_keys.into_iter())
            .zip(reference)
            .for_each(|((k, (_i, k_iter)), reference)| {
                assert_eq!(k.content(), reference);
                assert_eq!(k_iter.content(), reference);
            });
    }
}
