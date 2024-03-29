//! Securely serialize cryptographic objects

use crate::errors::UnwrappingError;
use crate::serialization::cleartext_serialization::*;
use crate::{AeadCipher, Key256, WrappingError};
use std::{io::Cursor, ops::DerefMut};

use zeroize::*;

/// An object to wrap and unwrap cryptographic objects implemented in the crate
pub struct CryptoWrapper {
    /// The underlying authenticated cipher used to encrypt the objects
    cipher: AeadCipher,
}

/// Objects that can be wrapped to a bytes sequence
pub trait Wrappable: SerializableCleartext + DeserializableCleartext {}
impl<T> Wrappable for T where T: SerializableCleartext + DeserializableCleartext {}

impl CryptoWrapper {
    /// Initialize a new wrapper
    #[must_use]
    pub fn from_key(key: Key256) -> Self {
        CryptoWrapper {
            cipher: AeadCipher::from_key(key),
        }
    }

    /// Wrap an object to a ciphertext: serialize the object and encrypt the
    /// resulting bytes
    pub fn wrap<T: Wrappable>(
        &self,
        object: &T,
    ) -> Result<Vec<u8>, WrappingError> {
        // try to avoid reallocations by constructing a vector with the right
        // length from the beginning
        let plain_length = object.cleartext_serialization_length();

        let mut buf = Zeroizing::new(vec![0u8; plain_length]);

        // serialize the object to plaintext
        object.serialize_cleartext(&mut buf.deref_mut().as_mut_slice())?;

        // encrypt it
        // If the given length overflows, the call to 'encrypt' will return an
        // error
        let mut ct = vec![0u8; plain_length + AeadCipher::CIPHERTEXT_EXPANSION];

        self.cipher.encrypt(&buf, &mut ct)?;

        Ok(ct)
    }

    /// Unwrap an object from a sequence of bytes
    pub fn unwrap<T: Wrappable>(
        &self,
        bytes: &[u8],
    ) -> Result<T, UnwrappingError> {
        let buf = Zeroizing::new(self.cipher.decrypt_to_vec(bytes)?);

        let mut cursor = Cursor::new(&*buf);

        Ok(T::deserialize_cleartext(&mut cursor)?)
    }
}
