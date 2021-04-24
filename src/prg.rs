//! Pseudo-random generator

use crate::insecure_clone::private::InsecureClone;
use crate::key::{Key, Key256, KeyAccessor};
use crate::serialization::cleartext_serialization::*;
use crate::serialization::errors::*;

use chacha20::cipher::{
    NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek,
};
use chacha20::ChaCha20;
use clear_on_drop::clear_stack_on_return;
use zeroize::Zeroize;

use std::ops::Range;
use std::vec::Vec;

/// Pseudo random generator.
///
/// ## Evaluation algorithm
///
/// A PRG takes a random seed (a.k.a. a key) as input to derive a longer
/// pseudo-random bytes sequence. It can be seen as a single-use stream-cipher.
/// Here, the PRG is simply implemented using Chacha20 and a fixed IV. It can
/// be used to fill a buffer with pseudo random bytes, or to derive keys
/// (although, generally speaking, a PRF a is preferred in that case, to avoid
/// security errors).
/// The interest of using a PRG instead of the PRF might be efficiency: the PRG
/// implementation is twice as fast as the PRF one. This is to be expected as
/// the PRF uses a hash function, a primitive that is way more complicated than
/// a block cipher or a stream cipher. For the actual difference on your
/// platform, run `cargo bench`.
///
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Prg {
    key: Key256,
}

impl Prg {
    const PRG_NONCE: [u8; 12] = [0u8; 12];

    /// Construct a PRG from a 256 bits key
    pub fn from_key(key: Key256) -> Prg {
        Prg { key }
    }

    /// Construct a PRG from a new random key
    #[allow(clippy::new_without_default)] // This is done on purpose to avoid
                                          // involuntary creation of a PRG with
                                          // a random key
    pub fn new() -> Prg {
        let key = Key256::new();
        Prg { key }
    }

    /// Fill a slice with pseudo-random bytes resulting from the PRG evaluation.
    pub fn fill_pseudo_random_bytes(&self, output: &mut [u8]) {
        // while we wait for the Chacha implementation to implement zeroize,
        // use the stack-clearing interface from clear_on_drop
        clear_stack_on_return(1, || {
            let mut cipher =
                ChaCha20::new_var(self.key.content(), &Self::PRG_NONCE)
                    .unwrap();

            // set the bytes of the buffer to 0
            output.zeroize();
            cipher.apply_keystream(output);
        });
    }

    /// Fill a slice with pseudo-random bytes resulting from the PRG evaluation,
    /// with an offset of `offset` bytes. This allows for a more efficient
    /// evaluation when `offset` is large (instead of throwing away the prefix
    /// of the buffer) # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::Prg;
    ///
    /// let prg = Prg::new();
    /// let mut buf = [0u8;32];
    /// let mut buf_offset = [0u8;30];
    ///
    /// prg.fill_pseudo_random_bytes(&mut buf);
    /// prg.fill_offset_pseudo_random_bytes(2, &mut buf_offset);
    /// # assert_eq!(&buf[2..], &buf_offset[..]);
    /// ```
    pub fn fill_offset_pseudo_random_bytes(
        &self,
        offset: usize,
        output: &mut [u8],
    ) {
        // while we wait for the Chacha implementation to implement zeroize,
        // use the stack-clearing interface from clear_on_drop
        clear_stack_on_return(1, || {
            let mut cipher =
                ChaCha20::new_var(self.key.content(), &Self::PRG_NONCE)
                    .unwrap();

            cipher.seek(offset);
            // set the bytes of the buffer to 0
            output.zeroize();
            cipher.apply_keystream(output);
        });
    }
}

impl InsecureClone for Prg {
    fn insecure_clone(&self) -> Self {
        Prg {
            key: self.key.insecure_clone(),
        }
    }
}

/// Pseudo random generator used to derive cryptographic keys.
/// See `Prg` for more details of the PRG evaluation.
pub struct KeyDerivationPrg<KeyType: Key> {
    prg: Prg,
    _marker: std::marker::PhantomData<KeyType>,
}

impl<KeyType: Key> Zeroize for KeyDerivationPrg<KeyType> {
    fn zeroize(&mut self) {
        self.prg.zeroize();
    }
}

impl<KeyType: Key> Drop for KeyDerivationPrg<KeyType> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<KeyType: Key> InsecureClone for KeyDerivationPrg<KeyType> {
    fn insecure_clone(&self) -> Self {
        KeyDerivationPrg::<KeyType> {
            prg: self.prg.insecure_clone(),
            _marker: std::marker::PhantomData,
        }
    }
}

impl<KeyType: Key> KeyDerivationPrg<KeyType> {
    /// Construct a PRG intended for key derivation from a 256 bits key
    pub fn from_key(key: Key256) -> Self {
        Self {
            prg: Prg::from_key(key),
            _marker: std::marker::PhantomData,
        }
    }

    /// Construct a PRG intended for key derivation from a new random key
    #[allow(clippy::new_without_default)] // This is done on purpose to avoid
                                          // involuntary creation of a PRG with
                                          // a random key
    pub fn new() -> Self {
        Self {
            prg: Prg::new(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Derive a new key using the PRG. Modifying `key_index` parameter
    /// generates keys that are computationally pair-wise independent
    pub fn derive_key(&self, key_index: u32) -> KeyType {
        let offset = (key_index as usize) * KeyType::KEY_SIZE;
        // cannot use an array in the following line :(
        // use a vector instead until const generics for arrays are standardized
        // (in a way that fits us)
        let mut buf = vec![0u8; KeyType::KEY_SIZE];
        self.prg.fill_offset_pseudo_random_bytes(offset, &mut buf);

        KeyType::from_slice(&mut buf[..])
    }

    /// Derive a sequence of new keys using the PRG such that their key_index
    /// is in the `indexes` range. The keys in the output are sorted by
    /// increasing index.
    pub fn derive_keys(&self, indexes: Range<u32>) -> Vec<KeyType> {
        let index_width = indexes.len();

        let mut res = Vec::<KeyType>::new();
        res.reserve(index_width);

        let mut buf = vec![0u8; (index_width as usize) * KeyType::KEY_SIZE];
        let offset = (indexes.start as usize) * KeyType::KEY_SIZE;

        self.prg.fill_offset_pseudo_random_bytes(offset, &mut buf);

        for i in 0..index_width {
            let range_begin = (i as usize) * KeyType::KEY_SIZE;
            let range_end = (i + 1) * KeyType::KEY_SIZE;
            res.push(KeyType::from_slice(&mut buf[range_begin..range_end]));
        }

        res
    }

    /// Derive a pair of new keys using the PRG. The returned pair of keys
    /// `(k1,k2) have index `key_index` and `key_index+1` respectively.
    pub fn derive_key_pair(&self, key_index: u32) -> (KeyType, KeyType) {
        let mut buf = vec![0u8; 2 * KeyType::KEY_SIZE];

        self.prg.fill_offset_pseudo_random_bytes(
            key_index as usize * KeyType::KEY_SIZE,
            &mut buf,
        );

        (
            KeyType::from_slice(&mut buf[..KeyType::KEY_SIZE]),
            KeyType::from_slice(&mut buf[KeyType::KEY_SIZE..]),
        )
    }
}

impl SerializableCleartextContent for Prg {
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

impl<KeyType: Key> SerializableCleartextContent for KeyDerivationPrg<KeyType> {
    fn serialization_content_byte_size(&self) -> usize {
        self.prg.serialization_content_byte_size()
    }
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        self.prg.serialize_content(writer)
    }
}

impl DeserializableCleartextContent for Prg {
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        Ok(Prg::from_key(Key256::deserialize_content(reader)?))
    }
}

impl<KeyType: Key> DeserializableCleartextContent
    for KeyDerivationPrg<KeyType>
{
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        Ok(KeyDerivationPrg::<KeyType> {
            prg: Prg::deserialize_content(reader)?,
            _marker: std::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_offset_correctness(offset: usize, buf_len: usize) -> bool {
        let prg = Prg::new();
        let mut v1 = vec![0u8; buf_len + offset];
        let mut v2 = vec![0u8; buf_len];

        prg.fill_pseudo_random_bytes(&mut v1);
        prg.fill_offset_pseudo_random_bytes(offset, &mut v2);

        v1[offset..] == v2[..]
    }

    #[test]
    fn offset_correctness() {
        const TEST_BUF_LEN: usize = 1024_usize;
        for offset in 0..1025 {
            assert!(test_offset_correctness(offset, TEST_BUF_LEN), "Full and offset PRG generation do not match for offset {} and buffer length {}",offset, TEST_BUF_LEN);
        }
    }

    fn key_derivation<KeyType: Key + KeyAccessor>() {
        let k = Key256::new();
        let k_dup = k.insecure_clone();
        let prg = Prg::from_key(k);
        let derivation_prg = KeyDerivationPrg::<KeyType>::from_key(k_dup);

        let key_range = 0..300u32;
        let seq_keys = derivation_prg.derive_keys(key_range.clone());

        for key_index in key_range {
            let mut buf = vec![0u8; KeyType::KEY_SIZE];
            prg.fill_offset_pseudo_random_bytes(
                (key_index as usize) * KeyType::KEY_SIZE,
                &mut buf,
            );
            let k_deriv = derivation_prg.derive_key(key_index);

            assert!(k_deriv.content() == buf);
            assert_eq!(seq_keys[key_index as usize].content(), buf);
        }
    }

    fn key_pairs<KeyType: Key + KeyAccessor>() {
        let key_range = 0..300u32;

        for key_index in key_range {
            let k = Key256::new();
            let k_dup = k.insecure_clone();
            let prg = Prg::from_key(k);
            let derivation_prg = KeyDerivationPrg::<KeyType>::from_key(k_dup);

            let mut buf = vec![0u8; 2 * KeyType::KEY_SIZE];
            prg.fill_offset_pseudo_random_bytes(
                (key_index as usize) * KeyType::KEY_SIZE,
                &mut buf,
            );
            let (k_deriv_1, k_deriv_2) =
                derivation_prg.derive_key_pair(key_index);

            assert_eq!(k_deriv_1.content(), &buf[..KeyType::KEY_SIZE]);
            assert_eq!(k_deriv_2.content(), &buf[KeyType::KEY_SIZE..]);
        }
    }

    #[test]
    fn key_derivation_256() {
        key_derivation::<Key256>();
        key_pairs::<Key256>();
    }
}
