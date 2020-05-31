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
            params.key(&self.key.content);
            params.hash_length(out_length);
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

#[cfg(all(test, feature = "with-bench"))]
mod tests {
    use super::*;
    use test::Bencher;
    
    macro_rules! prf_bench {
        ($name:ident ,$size:expr) => {
            #[bench]
            fn $name(b: &mut Bencher) {
                let prf = Prf::new();
                let in_buffer = [0u8; 16];
                let mut out_buffer = [0u8; $size];
                b.iter(|| prf.fill_bytes(&in_buffer, &mut out_buffer));
            }
        };
    }

    prf_bench!(prf_16_bytes, 16);
    prf_bench!(prf_32_bytes, 32);
    prf_bench!(prf_64_bytes, 64);
    prf_bench!(prf_128_bytes, 128);
    prf_bench!(prf_256_bytes, 256);
    prf_bench!(prf_512_bytes, 512);
}
