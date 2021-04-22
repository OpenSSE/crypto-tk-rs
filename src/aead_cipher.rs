//! Authenticated Encryption

use chacha20poly1305::{
    aead::{AeadInPlace, NewAead},
    Tag,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};

// use clear_on_drop::clear_stack_on_return;
use rand::RngCore;
use zeroize::Zeroize;

// use std::vec::Vec;

use crate::{insecure_clone::private::InsecureClone, EncryptionError};
use crate::{DecryptionError, KeyDerivationPrf};
use crate::{Key256, KeyAccessor};

/// Authenticated encryption & decryption
///
/// AeadCipher implements authenticated encryption (and decryption), using the Chacha20 stream cipher and Poly1305 universal hash function.
/// To avoid having to keep a state, the nonce is randomly generated. Unfortunately, Chacha20 has small nonces (96 bits), which means that replay attacks might happen very quickly (after about 2^32 blocks encrypted with the same key). In order to avoid such attacks, we use a 128 bits nonce which is itself used to derive a encryption key using a PRF keyed with the main key.
/// This allows us to encrypt a very large number of messages using the same main key.
///
/// ## Key derivation
/// Let `K` be the main key, and `m` the message to encrypt.
/// Let `IV` be a random 128 bits string, and set `K_e = Prf(K,IV)`.
/// The ciphertext would be `c = Enc(K_e,IV,m)` where `Enc` is the Chacha20+Poly1305 encryption algorithm. Note that there is no issue in reusing the nonce here as Chacha20+Poly1305 is a nonce-based scheme (and not random-IV-based), and that `K_e` is unique (with high probability) for every message.
///
/// This approach has been adopted by Google on their Cloud, exactly for the same reason: avoiding nonce reuse (or more exactly, nonce collision). See their [CCS 2017 paper]() for more details and security proofs.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct AeadCipher {
    key_derivation_prf: KeyDerivationPrf<Key256>,
}

impl InsecureClone for AeadCipher {
    fn insecure_clone(&self) -> Self {
        AeadCipher {
            key_derivation_prf: self.key_derivation_prf.insecure_clone(),
        }
    }
}

impl AeadCipher {
    /// Size of a nonce, in bytes
    pub const NONCE_SIZE: usize = 16;

    /// Size of the authentication tag, in bytes
    pub const TAG_LENGTH: usize = 16;

    /// The ciphertext expansion, i.e. the number of additional bytes due to the encryption
    pub const CIPHERTEXT_EXPANSION: usize =
        AeadCipher::NONCE_SIZE + AeadCipher::TAG_LENGTH;

    /// Construct a cipher from a 256 bits key
    pub fn from_key(key: Key256) -> AeadCipher {
        AeadCipher {
            key_derivation_prf: KeyDerivationPrf::<Key256>::from_key(key),
        }
    }

    /// Encrypt a byte slice and write the result of the encryption in `ciphertext`.
    /// Returns an error if the `ciphertext` slice cannot contain the result, i.e. if it is not at least `CIPHERTEXT_EXPANSION` bytes longer than `plaintext`.
    pub fn encrypt(
        &self,
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> Result<(), EncryptionError> {
        if ciphertext.len() < plaintext.len() + AeadCipher::CIPHERTEXT_EXPANSION
        {
            return Err(EncryptionError::CiphertextLengthError {
                plaintext_length: plaintext.len(),
                ciphertext_length: ciphertext.len(),
            });
        }

        let mut iv = [0u8; AeadCipher::NONCE_SIZE];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut iv);

        // write the nonce at the beginning of the ciphertext
        ciphertext.copy_from_slice(&iv);

        // copy the plaintext
        ciphertext[AeadCipher::NONCE_SIZE..].copy_from_slice(plaintext);

        let encryption_key = self.key_derivation_prf.derive_key(&iv);
        let cipher =
            ChaCha20Poly1305::new_varkey(&encryption_key.content()).unwrap();

        let inner_nonce = Nonce::from_slice(&iv);
        let tag = cipher
            .encrypt_in_place_detached(&inner_nonce, b"", ciphertext)
            .map_err(|_| EncryptionError::InnerError())?;

        ciphertext[(AeadCipher::NONCE_SIZE + plaintext.len())..]
            .copy_from_slice(&tag);
        Ok(())
    }

    /// Decrypt a byte slice and write the result of the decryption in `plaintext`.
    /// Returns an error if the `plaintext` slice cannot contain the result, i.e. if it is not at least `CIPHERTEXT_EXPANSION` bytes smaller than `ciphertext`.
    /// Also returns an error if `ciphertext`'s length is smaller than `CIPHERTEXT_EXPANSION` bytes
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<(), DecryptionError> {
        if ciphertext.len() < AeadCipher::CIPHERTEXT_EXPANSION {
            return Err(DecryptionError::CiphertextLengthError(
                ciphertext.len(),
            ));
        }

        if ciphertext.len() > plaintext.len() + AeadCipher::CIPHERTEXT_EXPANSION
        {
            return Err(DecryptionError::PlaintextLengthError {
                plaintext_length: plaintext.len(),
                ciphertext_length: ciphertext.len(),
            });
        }

        let l = ciphertext.len();
        let iv = &ciphertext[0..AeadCipher::NONCE_SIZE];
        let tag = Tag::from_slice(&ciphertext[l - AeadCipher::TAG_LENGTH..]);

        // copy the ciphertext
        plaintext.copy_from_slice(
            &ciphertext[AeadCipher::NONCE_SIZE..l - AeadCipher::TAG_LENGTH],
        );

        let encryption_key = self.key_derivation_prf.derive_key(&iv);
        let cipher =
            ChaCha20Poly1305::new_varkey(&encryption_key.content()).unwrap();

        let inner_nonce = Nonce::from_slice(&iv);
        cipher
            .decrypt_in_place_detached(&inner_nonce, b"", plaintext, tag)
            .map_err(|_| DecryptionError::InnerError())?;

        Ok(())
    }
}
