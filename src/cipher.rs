//! Encryption

use chacha20::ChaCha20;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    Nonce,
};

// use clear_on_drop::clear_stack_on_return;
use rand::RngCore;
use zeroize::Zeroize;

// use std::vec::Vec;
use crate::insecure_clone::{private::InsecureClone, CryptographyClone};
use crate::serialization::cleartext_serialization::{
    DeserializableCleartextContent, SerializableCleartextContent,
};
use crate::serialization::errors::CleartextContentDeserializationError;

use crate::EncryptionError;
use crate::{DecryptionError, KeyDerivationPrf};
use crate::{Key256, KeyAccessor};

/// Encryption & decryption (unauthenticated)
///
/// Cipher implements encryption (and decryption), using the Chacha20 stream
/// cipher. You probably want to use authenticated encryption for increased
/// security. Use unauthenticated encryption only if you know what you are doing
/// To avoid having to keep a state, the nonce is randomly generated.
/// Unfortunately, Chacha20 has small nonces (96 bits), which means that replay
/// attacks might happen very quickly (after about 2^32 blocks encrypted with
/// the same key). In order to avoid such attacks, we use a 128 bits nonce which
/// is itself used to derive a encryption key using a PRF keyed with the main
/// key. This allows us to encrypt a very large number of messages using the
/// same main key.
///
/// ## Key derivation
/// Let `K` be the main key, and `m` the message to encrypt.
/// Let `IV` be a random 128 bits string, and set `K_e = Prf(K,IV)`.
/// The ciphertext would be `c = Enc(K_e,IV,m)` where `Enc` is the
/// Chacha20+Poly1305 encryption algorithm. Note that there is no issue in
/// reusing the nonce here as Chacha20+Poly1305 is a nonce-based scheme (and not
/// random-IV-based), and that `K_e` is unique (with high probability) for every
/// message.
///
/// This approach has been thoroughly described by Gueron and Bellare, with examples of real-world application in [their CCS'17 paper](https://eprint.iacr.org/2017/702.pdf).
/// We refer to this document for the full proof of security of this
/// construction.

#[derive(Zeroize)]
#[zeroize(drop)]
pub struct Cipher {
    key_derivation_prf: KeyDerivationPrf<Key256>,
}

impl InsecureClone for Cipher {
    fn insecure_clone(&self) -> Self {
        Cipher {
            key_derivation_prf: self.key_derivation_prf.insecure_clone(),
        }
    }
}

impl CryptographyClone for Cipher {}

impl Cipher {
    /// Size of a nonce, in bytes
    pub const NONCE_SIZE: usize = 16;

    const CHACHA20_NONCE_LENGTH: usize = 12;

    /// The ciphertext expansion, i.e. the number of additional bytes due to the
    /// encryption
    pub const CIPHERTEXT_EXPANSION: usize = Cipher::NONCE_SIZE;

    /// Construct a cipher from a 256 bits key
    #[must_use]
    pub fn from_key(key: Key256) -> Cipher {
        Cipher {
            key_derivation_prf: KeyDerivationPrf::<Key256>::from_key(key),
        }
    }

    /// Encrypt a byte slice and write the result of the encryption in
    /// `ciphertext`. Returns an error if the `ciphertext` slice cannot
    /// contain the result, i.e. if it is not at least `CIPHERTEXT_EXPANSION`
    /// bytes longer than `plaintext`.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), EncryptionError> {
        if ciphertext
            .len()
            .saturating_sub(Cipher::CIPHERTEXT_EXPANSION)
            < plaintext.len()
        {
            return Err(EncryptionError::CiphertextLengthError {
                plaintext_length: plaintext.len(),
                ciphertext_length: ciphertext.len(),
            });
        }

        let mut iv = [0u8; Cipher::NONCE_SIZE];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut iv);

        // write the nonce at the beginning of the ciphertext
        ciphertext[..Cipher::NONCE_SIZE].copy_from_slice(&iv);

        // copy the plaintext
        ciphertext[Cipher::NONCE_SIZE..(Cipher::NONCE_SIZE + plaintext.len())]
            .copy_from_slice(plaintext);

        let encryption_key = self.key_derivation_prf.derive_key(&iv);
        let chacha_key = chacha20::Key::from_slice(encryption_key.content());
        let inner_nonce =
            Nonce::from_slice(&iv[..Cipher::CHACHA20_NONCE_LENGTH]);
        let mut cipher = ChaCha20::new(chacha_key, inner_nonce);

        cipher.apply_keystream(
            &mut ciphertext
                [Cipher::NONCE_SIZE..(Cipher::NONCE_SIZE + plaintext.len())],
        );

        Ok(())
    }

    /// Decrypt a byte slice and write the result of the decryption in
    /// `plaintext`. Returns an error if the `plaintext` slice cannot
    /// contain the result, i.e. if it is not at least `CIPHERTEXT_EXPANSION`
    /// bytes smaller than `ciphertext`. Also returns an error if
    /// `ciphertext`'s length is smaller than `CIPHERTEXT_EXPANSION` bytes
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), DecryptionError> {
        let l = ciphertext.len();
        if l < Cipher::CIPHERTEXT_EXPANSION {
            return Err(DecryptionError::CiphertextLengthError(l));
        }

        if l > plaintext.len() + Cipher::CIPHERTEXT_EXPANSION {
            return Err(DecryptionError::PlaintextLengthError {
                plaintext_length: plaintext.len(),
                ciphertext_length: l,
            });
        }

        // The first test prevents an underflow
        let real_plaintext_length = l - Cipher::CIPHERTEXT_EXPANSION;
        let iv = &ciphertext[0..Cipher::NONCE_SIZE];

        // copy the ciphertext
        plaintext[..real_plaintext_length]
            .copy_from_slice(&ciphertext[Cipher::NONCE_SIZE..]);

        let encryption_key = self.key_derivation_prf.derive_key(iv);
        let chacha_key = chacha20::Key::from_slice(encryption_key.content());
        let inner_nonce =
            Nonce::from_slice(&iv[..Cipher::CHACHA20_NONCE_LENGTH]);
        let mut cipher = ChaCha20::new(chacha_key, inner_nonce);

        cipher.apply_keystream(&mut plaintext[..real_plaintext_length]);

        Ok(())
    }
}

impl SerializableCleartextContent for Cipher {
    fn serialization_content_byte_size(&self) -> usize {
        self.key_derivation_prf.serialization_content_byte_size()
    }
    fn serialize_content(
        &self,
        writer: &mut dyn std::io::Write,
    ) -> Result<usize, std::io::Error> {
        self.key_derivation_prf.serialize_content(writer)?;

        Ok(self.serialization_content_byte_size())
    }
}

impl DeserializableCleartextContent for Cipher {
    fn deserialize_content(
        reader: &mut dyn std::io::Read,
    ) -> Result<Self, CleartextContentDeserializationError> {
        Ok(Cipher {
            key_derivation_prf:
                KeyDerivationPrf::<Key256>::deserialize_content(reader)?,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use crate::Key;

    use super::*;

    const TEST_PLAINTEXT: &[u8] = b"Test plaintext";

    #[test]
    fn encryption_errors() {
        let plaintext = TEST_PLAINTEXT;
        let mut ciphertext = [0u8; 8];

        let k = Key256::new();
        let cipher = Cipher::from_key(k);
        cipher
            .encrypt(plaintext, &mut ciphertext)
            .expect_err("Expected invalid ciphertext length error");
    }

    #[test]
    fn encryption_correctness() {
        let plaintext = TEST_PLAINTEXT;
        let mut ciphertext =
            vec![0u8; plaintext.len() + Cipher::CIPHERTEXT_EXPANSION];
        let mut dec_result = vec![0u8; plaintext.len()];

        let k = Key256::new();
        let cipher = Cipher::from_key(k);
        cipher.encrypt(plaintext, &mut ciphertext).unwrap();

        cipher.decrypt(&ciphertext, &mut dec_result).unwrap();

        assert_eq!(plaintext, &dec_result[..]);
    }

    #[test]
    fn decryption_errors() {
        let plaintext = TEST_PLAINTEXT;
        let mut ciphertext =
            vec![0u8; plaintext.len() + Cipher::CIPHERTEXT_EXPANSION];
        let mut dec_result = vec![0u8; plaintext.len() - 1];

        let k = Key256::new();
        let cipher = Cipher::from_key(k);
        cipher.encrypt(plaintext, &mut ciphertext).unwrap();

        match cipher
            .decrypt(&ciphertext[0..1], &mut dec_result)
            .unwrap_err()
        {
            DecryptionError::CiphertextLengthError(_) => (),
            _ => panic!("Invalid Error"),
        }

        match cipher.decrypt(&ciphertext, &mut dec_result).unwrap_err() {
            DecryptionError::PlaintextLengthError { .. } => (),
            _ => panic!("Invalid Error"),
        }
    }
}
