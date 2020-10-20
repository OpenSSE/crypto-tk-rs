//! Pseudo-random generator

use crate::key::{Key, Key256, KeyAccessor};
use chacha20::cipher::{
    NewStreamCipher, SyncStreamCipher, SyncStreamCipherSeek,
};
use chacha20::ChaCha20;
use clear_on_drop::clear_stack_on_return;
use zeroize::Zeroize;

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
///
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

    /// Fill a slice with pseudo-random bytes resulting from the PRG evaluation, with an offset of `offset` bytes.
    /// This allows for a more efficient evaluation when `offset` is large (instead of throwing away the prefix of the buffer)
    /// # Example
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
    ///
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

/// Pseudo random generator used to derive cryptographic keys.
/// See `Prg` for more details of the PRG evaluation.
pub struct KeyDerivationPrg<KeyType: Key> {
    prg: Prg,
    _marker: std::marker::PhantomData<*const KeyType>,
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

        return KeyType::from_slice(&mut buf[..]);
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

        return v1[offset..] == v2[..];
    }

    #[test]
    fn offset_correctness() {
        const TEST_BUF_LEN: usize = 1024_usize;
        for offset in 0..1025 {
            assert!(test_offset_correctness(offset, TEST_BUF_LEN), "Full and offset PRG generation do not match for offset {} and buffer length {}",offset, TEST_BUF_LEN);
        }
    }

    fn key_derivation<KeyType: Key + KeyAccessor>() {
        for key_index in 0..300u32 {
            let k = Key256::new();
            let k_dup = k.insecure_duplicate();

            let prg = Prg::from_key(k);
            let derivation_prg = KeyDerivationPrg::<KeyType>::from_key(k_dup);

            let mut buf = vec![0u8; KeyType::KEY_SIZE];
            prg.fill_offset_pseudo_random_bytes(
                (key_index as usize) * KeyType::KEY_SIZE,
                &mut buf,
            );
            let k_deriv = derivation_prg.derive_key(key_index);

            assert!(k_deriv.content() == buf);
        }
    }

    #[test]
    fn key_derivation_256() {
        key_derivation::<Key256>();
    }
}
