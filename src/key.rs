use rand::prelude::*;
use zeroize::{Zeroize, Zeroizing};

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Key256 {
    pub(crate) content: [u8; 64],
}

impl Key256 {
    pub fn new() -> Key256 {
        let mut rng = thread_rng();
        // we cannot call rng.gen() on 64 elements arrays (it is limited to 32 elements)
        // instead, create a zeroizing buffer and fill it with rng.fill_bytes
        let mut randomness = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(&mut *randomness);

        let k = Key256 {
            content: *randomness,
        };

        k
    }

    pub fn new_from(randomness: &mut [u8; 64]) -> Key256 {
        let k = Key256 {
            content: *randomness,
        };
        randomness.zeroize();
        k
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

        let k = Key256::new_from(&mut buf);

        // cannot compare 64 elements arrays (the comparison works for at most
        // 32 elements). We have to split the comparison in two
        assert_eq!(&k.content[0..32], &buf_copy[0..32]);
        assert_eq!(&k.content[32..64], &buf_copy[32..64]);

        assert_eq!(&buf[0..32], [0u8; 32]);
        assert_eq!(&buf[32..64], [0u8; 32]);
    }
}
