//! Secret Keys

use rand::prelude::*;
use zeroize::Zeroize;

/// A 256 bits (64 bytes) secret key. The key is zeroed upon drop.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Key256 {
    content: [u8; 32],
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
        let mut k = Key256 { content: [0u8; 32] };
        csprng.fill_bytes(&mut k.content);
        k
    }

    /// Construct a `Key256` key from random data coming out of the OS CSPRNG.
    pub fn new() -> Key256 {
        let mut rng = thread_rng();
        Key256::generate(&mut rng)
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
    /// let mut buf = [1u8;32];
    /// let k = Key256::from_bytes(&mut buf);
    /// /// buf is set to all 0
    /// # assert_eq!(&buf[..], &[0u8; 32][..]);
    /// ```
    pub fn from_bytes(randomness: &mut [u8; 32]) -> Key256 {
        let k = Key256 {
            content: *randomness,
        };
        randomness.zeroize();
        k
    }

    /// Get the content of the key
    /// This accessor in only available to `crypto-tk` crate.
    pub(crate) fn content(&self) -> &[u8] {
        &self.content
    }

    /// Duplicates the key.
    /// Would be similar to `clone()`, except we want to make sure that the user knows this leads to security issues.
    /// This function is only available in `test` mode (it should not be used in production code).
    #[cfg(test)]
    pub fn insecure_duplicate(&self) -> Key256 {
        return Key256 {
            content: self.content.clone(),
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_from() {
        let mut buf: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        ];

        let mut buf_copy = [0u8; 32];
        buf_copy.copy_from_slice(&buf);

        let k = Key256::from_bytes(&mut buf);

        assert_eq!(k.content, buf_copy);

        assert_eq!(k.content, k.insecure_duplicate().content);

        // check that the buffer we built the key from has been cleared
        assert_eq!(buf, [0u8; 32]);
    }
}
