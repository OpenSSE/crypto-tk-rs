//! Errors
use thiserror::Error;

use crate::serialization;
/// Encryption error
#[derive(Error, Debug)]
pub enum EncryptionError {
    /// Invalid ciphertext length
    #[error("Encryption Error - The length of the ciphertext slice for a plaintext of size {plaintext_length} is invalid ({ciphertext_length})")]
    CiphertextLengthError {
        /// plaintext length
        plaintext_length: usize,
        /// ciphertext length
        ciphertext_length: usize,
    },
    /// Opaque error during the encryption
    #[error("Encryption Error - Inner Error")]
    InnerError(#[from] aead::Error),
}

/// Decryption error
#[derive(Error, Debug)]
pub enum DecryptionError {
    /// Invalid ciphertext length
    #[error("Decryption Error - The length of the ciphertext slice is invalid  because it is smaller than the ciphertext expansion ({0} < 32)")]
    CiphertextLengthError(usize),
    /// Invalid plaintext length
    #[error("Decryption Error - The length of the plaintext  slice for a ciphertext of size {ciphertext_length} is invalid ({plaintext_length})")]
    PlaintextLengthError {
        /// plaintext length
        plaintext_length: usize,
        /// ciphertext length
        ciphertext_length: usize,
    },
    /// Opaque error during the encryption
    #[error("Decryption Error - Inner Error")]
    InnerError(#[from] aead::Error),
}

/// Error while wrapping a cryptographic object
#[derive(Error, Debug)]
pub enum WrappingError {
    /// Ecnryption error
    #[error("WrappingError - error during encryption: {0}")]
    DecryptionError(#[from] EncryptionError),
    /// Deserialization error
    #[error("WrappingError - IO error during serialization: {0}")]
    SerializationError(#[from] std::io::Error),
}

/// Error while unwrapping a cryptographic object
#[derive(Error, Debug)]
pub enum UnwrappingError {
    /// Decryption error
    #[error("UnwrappingError - error during decryption: {0}")]
    DecryptionError(#[from] DecryptionError),
    /// Deserialization error
    #[error("UnwrappingError - error during deserialization: {0}")]
    DeserializationError(
        #[from] serialization::errors::CleartextDeserializationError,
    ),
}
