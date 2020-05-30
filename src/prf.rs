//! Pseudo-random function

use crate::key::Key256;

use blake2b_simd;
use clear_on_drop::clear::Clear;
use zeroize::Zeroize;

/// Pseudo random function impl
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Prf {
    key: Key256,
}

impl Prf {
    /// Construct a PRF from a 256 bits key
    pub fn from_key(key: Key256) -> Prf {
        Prf { key }
    }

    /// Construct a PRF from a new random key
    pub fn new() -> Prf {
        let key = Key256::new();
        Prf { key }
    }

    /// Fill a slice with pseudo-random bytes resulting from the PRF evaluation
    pub fn fill_bytes(self: &Self, input: &[u8], output: &mut [u8]) {
        let mut hash: blake2b_simd::Hash;

        let mut remaining_length = output.len();
        let mut written_bytes = 0;

        let mut i = 0u64;
        while remaining_length > 0 {
            let out_length = remaining_length.min(blake2b_simd::OUTBYTES);

            let mut params = blake2b_simd::Params::new();
            params.hash_length(output.len());
            params.salt(&i.to_le_bytes());

            let mut state = params.to_state();
            state.update(input);

            hash = state.finalize();
            output[written_bytes..written_bytes + out_length].copy_from_slice(hash.as_bytes());

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
