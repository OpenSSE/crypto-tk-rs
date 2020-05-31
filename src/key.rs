//! Secret Keys

use rand::prelude::*;
use zeroize::{Zeroize, Zeroizing};

/// A 256 bits (64 bytes) secret key. The key is zeroed upon drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Key256 {
    content: [u8; 64],
}

impl Key256 {
    /// Construct a `Key256` key from random data coming out of a
    /// cryptographically-secure PRNG.
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// # extern crate rand;
    /// use crypto_tk_rs::Key256;
    /// use rand::prelude::*;
    ///
    /// let k = Key256::generate(&mut thread_rng());
    /// ```
    pub fn generate<R>(csprng: &mut R) -> Key256
    where
        R: CryptoRng + RngCore,
    {
        // we cannot call csprng.gen() on 64 elements arrays (it is limited to 32 elements)
        // instead, create a zeroizing buffer and fill it with rng.fill_bytes
        let mut randomness = Zeroizing::new([0u8; 64]);
        csprng.fill_bytes(&mut *randomness);

        let k = Key256 {
            content: *randomness,
        };

        k
    }

    /// Construct a `Key256` key from random data coming out of the OS CSPRNG.
    pub fn new() -> Key256 {
        let mut rng = thread_rng();
        return Key256::generate(&mut rng);
    }

    /// Construct a `Key256` key from a slice of bytes and zero the slice.
    ///
    /// # Warning
    /// The input slice `randomness` will be zero after the function returns.
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::Key256;
    ///
    /// /// Initializes a new key with bytes all set to `0x01`
    /// let mut buf = [1u8;64];
    /// let k = Key256::from_bytes(&mut buf);
    /// /// buf is set to all 0
    /// # assert_eq!(&buf[..], &[0u8; 64][..]);
    /// ```
    pub fn from_bytes(randomness: &mut [u8; 64]) -> Key256 {
        let k = Key256 {
            content: *randomness,
        };
        randomness.zeroize();
        k
    }

    /// Get the content of the key
    pub(crate) fn content(&self) -> &[u8] {
        &self.content
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_from() {
        let mut buf: [u8; 64] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
            0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
            0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
        ];

        let mut buf_copy = [0u8; 64];
        buf_copy.copy_from_slice(&buf);

        let k = Key256::from_bytes(&mut buf);

        // cannot compare 64 elements arrays (the comparison works for at most
        // 32 elements). We have to compare slices
        assert_eq!(&k.content[..], &buf_copy[..]);

        // check that the buffer we built the key from has been cleared
        assert_eq!(&buf[..], &[0u8; 64][..]);
    }
}
