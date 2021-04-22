//! Errors
use thiserror::Error;
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
    InnerError(),
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
    InnerError(),
}
