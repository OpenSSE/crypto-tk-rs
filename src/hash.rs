//! Hashing value to bytes

/// A finalized hash value with constant-time equality and an accessible `u8` representation
/// This implementation uses Blake2b, and the `blake2b_simd` crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash {
    inner: blake2b_simd::Hash,
}

impl Hash {
    /// The size of the hash value, in bytes
    pub const HASH_SIZE: usize = 64;

    /// Creates a new hash value from the input data
    pub fn new(data: &[u8]) -> Hash {
        Hash {
            inner: blake2b_simd::blake2b(data),
        }
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl PartialEq<[u8]> for Hash {
    fn eq(&self, other: &[u8]) -> bool {
        self.inner.eq(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_HASH: &str = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
                          d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
    const ONE_BLOCK_HASH: &str = "865939e120e6805438478841afb739ae4250cf372653078a065cdcfffca4caf7\
                              98e6d462b65d658fc165782640eded70963449ae1500fb0f24981d7727e22c41";
    const THOUSAND_HASH: &str = "1ee4e51ecab5210a518f26150e882627ec839967f19d763e1508b12cfefed148\
                             58f6a1c9d1f969bc224dc9440f5a6955277e755b9c513f9ba4421c5e50c8d787";

    const LONG_VALUE: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d";
    const LONG_HASH: &str = "e0721e02517aedfa4e7e9ba503e025fd46e714566dc889a84cbfe56a55dfbe2fc4938ac4120588335deac8ef3fa229adc9647f54ad2e3472234f9b34efc46543";

    const FOX_VALUE: &[u8] = b"The quick brown fox jumps over the lazy dog";
    const FOX_HASH: &str = "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918";

    #[test]
    fn test_vectors() {
        let vectors = &[
            (&b""[..], EMPTY_HASH),
            (&[0; 128], ONE_BLOCK_HASH),
            (&[0; 1000], THOUSAND_HASH),
            (FOX_VALUE, FOX_HASH),
        ];

        for &(input, hash) in vectors {
            let expected = hex::decode(hash).unwrap();
            let hash = Hash::new(input);
            assert_eq!(hash, expected[..]);
        }

        let vectors = &[(LONG_VALUE, LONG_HASH)];
        for &(input_str, hash) in vectors {
            let input = hex::decode(input_str).unwrap();

            let expected = hex::decode(hash).unwrap();
            let hash = Hash::new(input.as_slice());
            assert_eq!(hash, expected[..]);
        }
    }
}
