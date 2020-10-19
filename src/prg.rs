//! Pseudo-random generator

use crate::key::Key256;
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

    /// Construct a PRF from a 256 bits key
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
}
