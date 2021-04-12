//! Serialization and deserialization of cryptographic objects

/// Errors raised by the module's functions
pub mod errors;

/// (De)Serialization in cleartext of the objects
pub(crate) mod cleartext_serialization;
/// Tags identifying the different object types
pub(crate) mod tags;
