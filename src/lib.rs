#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! A Rust toolkit for cryptographic primitives useful to implement
//! cryptographic algorithms and protocols (in particular searchable
//! encryption, which this crate has been designed for).
//!
//! ## About
//! Searchable encryption protocols, like other cryptographic
//! protocols, rely on high level cryptographic features such as
//! pseudo-random functions, hash functions, or encryption schemes.
//!  This toolkit provides interfaces and implementations of these
//! features in Rust.
//!
//! ## Disclaimer
//!
//! This is code for a **research project**. It **should not be used in
//! production**: the code lacks good Rust security practice, and it has
//! never been externally reviewed.

pub mod key;
pub mod prf;
pub mod utils;

// Export everything public modules
pub use crate::key::*;
pub use crate::prf::*;
pub use crate::utils::*;
