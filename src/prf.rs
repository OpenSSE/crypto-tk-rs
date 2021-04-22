//! Pseudo-random function

use crate::insecure_clone::private::InsecureClone;
use crate::key::{Key, Key256, KeyAccessor};
use crate::serialization::cleartext_serialization::*;
use crate::serialization::errors::*;

use clear_on_drop::clear::Clear;
use zeroize::Zeroize;

/// Pseudo random function.
///
/// ## Evaluation algorithm
///
/// The PRF is based on Blake2b's keyed mode associated with a counter.
/// The main attacks we want to prevent here, aside from weak
/// pseudo-randomness issues that are prevented by the use of Blake2,
/// are length-extension attacks: when called to output 16 bytes, the PRF
/// should not output the prefix of the output for 32 bytes.
/// More generally, we would like to specialize the PRF on its output length
/// (as it has been done with the original C++ `crypto-tk` implementation,
/// thought the use of templates), but the absence of const generics in Rust
/// prevents us to do so. Hence, this is ensured during the evaluation (the
/// `fill_bytes` function).
///
/// Note that Blake2 normally only outputs at most 64 bytes, while we would like
/// to be able to produce larger outputs. As a consequence, we use Blake2 in a
/// counter mode to produce the successive 64-bytes-or-less blocks needed.
/// For each block, we use the input as Blake2's input, the PRF key as its key,
/// the block's index as salt, and the total length as personalization.
/// Those last two parameters are little-endian encoded.
///
///
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Prf {
    key: Key256,
}

impl InsecureClone for Prf {
    fn insecure_clone(&self) -> Self {
        Prf {
            key: self.key.insecure_clone(),
        }
    }
}

impl Prf {
    /// Construct a PRF from a 256 bits key
    pub fn from_key(key: Key256) -> Prf {
        Prf { key }
    }

    /// Construct a PRF from a new random key
    #[allow(clippy::new_without_default)] // This is done on purpose to avoid
                                          // involuntary creation of a PRF with
                                          // a random key
    pub fn new() -> Prf {
        let key = Key256::new();
        Prf { key }
    }

    /// Fill a slice with pseudo-random bytes resulting from the PRF evaluation.
    /// The output length is used as a parameter of the PRF (think additional input data).
    /// The PRF is called in counter mode, so as to be able to fill slices larger than the base-PRF's output size.
    /// In this implementation based on Blake2b, the counter is input as the salt of the PRF evaluation.
    pub fn fill_bytes(&self, input: &[u8], output: &mut [u8]) {
        let mut hash: blake2b_simd::Hash;

        let mut remaining_length = output.len();
        let mut written_bytes = 0;
        let tot_output_len: u64 = output.len() as u64;
        let mut i = 0u64;

        while remaining_length > 0 {
            let out_length = remaining_length.min(blake2b_simd::OUTBYTES);

            let mut params = blake2b_simd::Params::new();
            params.key(self.key.content());
            params.hash_length(out_length);
            params.salt(&i.to_le_bytes());
            params.personal(&tot_output_len.to_le_bytes());

            let mut state = params.to_state();
            state.update(input);

            hash = state.finalize();
            output[written_bytes..written_bytes + out_length]
                .copy_from_slice(hash.as_bytes());

            // cleanup
            params.clear();
            // we must clean the hash variable
            // unfortunately, as blake2b_simd::Hash does not implement neither the Default nor the Zeroize trait, we cannot do that simply

            state.clear();

            remaining_length -= out_length;
            written_bytes += out_length;
            i += 1;
        }
    }
}
/// Pseudo random function used to derive cryptographic keys.
/// See `Prf` for more details of the PRF evaluation.
pub struct KeyDerivationPrf<KeyType: Key> {
    prf: Prf,
    _marker: std::marker::PhantomData<KeyType>,
}

impl<KeyType: Key> Zeroize for KeyDerivationPrf<KeyType> {
    fn zeroize(&mut self) {
        self.prf.zeroize();
    }
}

impl<KeyType: Key> Drop for KeyDerivationPrf<KeyType> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<KeyType: Key> InsecureClone for KeyDerivationPrf<KeyType> {
    fn insecure_clone(&self) -> Self {
        KeyDerivationPrf::<KeyType> {
            prf: self.prf.insecure_clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<KeyType: Key> KeyDerivationPrf<KeyType> {
    /// Construct a PRF for key derivation from a 256 bits key
    pub fn from_key(key: Key256) -> KeyDerivationPrf<KeyType> {
        Self {
            prf: Prf::from_key(key),
            _marker: std::marker::PhantomData,
        }
    }

    /// Construct a PRF for key derivation from a new random key
    #[allow(clippy::new_without_default)] // This is done on purpose to avoid
                                          // involuntary creation of a PRF with
                                          // a random key
    pub fn new() -> KeyDerivationPrf<KeyType> {
        Self {
            prf: Prf::new(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Derive a new pseudo-random key from the given input
    pub fn derive_key(&self, input: &[u8]) -> KeyType {
        let mut buf = vec![0u8; KeyType::KEY_SIZE];
        self.prf.fill_bytes(input, &mut buf);

        KeyType::from_slice(&mut buf)
    }
}

impl SerializableCleartextContent for Prf {
    fn serialization_content_byte_size(&self) -> usize {
        self.key.serialization_content_byte_size()
    }
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        self.key.serialize_content(writer)
    }
}

impl DeserializableCleartextContent for Prf {
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        Ok(Prf::from_key(Key256::deserialize_content(reader)?))
    }
}

impl<KeyType: Key> SerializableCleartextContent for KeyDerivationPrf<KeyType> {
    fn serialization_content_byte_size(&self) -> usize {
        self.prf.serialization_content_byte_size()
    }
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        self.prf.serialize_content(writer)
    }
}

impl<KeyType: Key> DeserializableCleartextContent
    for KeyDerivationPrf<KeyType>
{
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        Ok(Self {
            prf: Prf::deserialize_content(reader)?,
            _marker: std::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_uniqueness() {
        const N_TRIES: usize = 20;
        let mut outs = [[0u8; 20]; N_TRIES];
        let prf = Prf::new();

        #[allow(clippy::needless_range_loop)] // False positive
        for i in 0..outs.len() {
            prf.fill_bytes(&i.to_le_bytes(), &mut outs[i]);
        }

        for i in 0..outs.len() {
            let a1 = &outs[i];
            for a2 in &outs[0..i] {
                assert_ne!(a1, a2);
            }
        }
    }

    fn key_derivation<KeyType: Key + KeyAccessor>() {
        let k = Key256::new();
        let k_dup = k.insecure_clone();
        let prf = Prf::from_key(k);
        let derivation_prf = KeyDerivationPrf::<KeyType>::from_key(k_dup);

        let input = b"FooBar";
        let mut out = vec![0u8; KeyType::KEY_SIZE];

        prf.fill_bytes(input, &mut out);
        let k_deriv = derivation_prf.derive_key(input);

        assert!(k_deriv.content() == out);
    }

    #[test]
    fn key_derivation_256() {
        key_derivation::<Key256>();
    }
}
