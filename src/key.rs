//! Secret Keys

use crate::insecure_clone::private::InsecureClone;

use rand::prelude::*;
use std::ops::{Deref, DerefMut};

use zeroize::{Zeroize, Zeroizing};

/// Wrapper trait for key material
pub trait Key: InsecureClone + Zeroize {
    /// Size of the key in bytes
    const KEY_SIZE: usize;

    /// Construct a key from random data coming out of a
    /// cryptographically-secure PRNG.
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// # extern crate rand;
    /// use crypto_tk_rs::{Key256, Key};
    /// use rand::prelude::*;
    ///
    /// let k = Key256::generate(&mut thread_rng());
    /// ```
    fn generate<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + RngCore;

    /// Construct a key from random data coming out of the OS CSPRNG.
    fn new() -> Self;

    /// Construct a key from a slice of bytes and zero the slice.
    ///
    /// # Warning
    /// The  first `KEY_SIZE` bytes of the input slice `randomness` will be
    /// zero after the function returns.
    ///
    /// # Example
    /// ```
    /// # extern crate crypto_tk_rs;
    /// use crypto_tk_rs::{Key256, Key};
    ///
    /// /// Initializes a new key with bytes all set to `0x01`
    /// let mut buf = [1u8;32];
    /// let k = Key256::from_slice(&mut buf[..]);
    /// /// buf is set to all 0
    /// # assert_eq!(buf[..], [0u8; 32]);
    /// ```
    fn from_slice(bytes: &mut [u8]) -> Self;
}

pub(crate) trait KeyAccessor {
    fn content(&self) -> &[u8];
}

/// A 256 bits (64 bytes) secret key. The key is zeroed upon drop.
// #[derive(Zeroize)]
// #[zeroize(drop)]
pub struct Key256 {
    content: Zeroizing<[u8; 32]>,
    _marker: std::marker::PhantomPinned,
}
impl Key256 {
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
    /// # assert_eq!(buf, [0u8; 32]);
    /// ```
    pub fn from_bytes(randomness: &mut [u8; 32]) -> Key256 {
        let k = Key256 {
            content: Zeroizing::new(*randomness),
            _marker: std::marker::PhantomPinned,
        };
        randomness.zeroize();
        k
    }
}

impl Key for Key256 {
    const KEY_SIZE: usize = 32;

    fn generate<R>(csprng: &mut R) -> Self
    where
        R: CryptoRng + RngCore,
    {
        let mut k = Key256 {
            content: Zeroizing::new([0u8; 32]),
            _marker: std::marker::PhantomPinned,
        };
        csprng.fill_bytes(k.content.deref_mut());
        k
    }

    fn new() -> Self {
        let mut rng = thread_rng();
        Key256::generate(&mut rng)
    }

    fn from_slice(bytes: &mut [u8]) -> Self {
        let mut k = Self {
            content: Zeroizing::new([0u8; 32]),
            _marker: std::marker::PhantomPinned,
        };

        k.content.copy_from_slice(bytes);
        bytes.zeroize();

        k
    }
}

impl Zeroize for Key256 {
    fn zeroize(&mut self) {
        self.content.zeroize();
    }
}

impl InsecureClone for Key256 {
    fn insecure_clone(&self) -> Self {
        return Self {
            content: self.content.clone(),
            _marker: std::marker::PhantomPinned,
        };
    }
}

impl KeyAccessor for Key256 {
    /// Get the content of the key
    /// This accessor in only available to `crypto-tk` crate.
    fn content(&self) -> &[u8] {
        self.content.deref()
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

        let mut buf_copy_1 = [0u8; 32];
        let mut buf_copy_2 = [0u8; 32];
        buf_copy_1.copy_from_slice(&buf);
        buf_copy_2.copy_from_slice(&buf);

        let k1 = Key256::from_bytes(&mut buf);
        let k2 = Key256::from_slice(&mut buf_copy_2[..]);

        assert_eq!(k1.content, buf_copy_1);
        assert_eq!(k2.content, buf_copy_1);

        assert_eq!(k1.content, k1.insecure_clone().content);

        // check that the buffer we built the key from has been cleared
        assert_eq!(buf, [0u8; 32]);
        assert_eq!(buf_copy_2, [0u8; 32]);
    }
}
