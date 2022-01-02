#![forbid(unsafe_code)]
#![warn(missing_docs)]
// #![cfg_attr(feature = "with-bench", feature(test))]

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

// #[cfg(all(test, feature = "with-bench"))]
// extern crate test;

mod insecure_clone;

pub mod aead_cipher;
pub mod cipher;
pub mod errors;
pub mod hash;
pub mod key;
pub mod prf;
pub mod prg;
pub mod rcprf;
pub mod serialization;
pub mod utils;

// Export everything public in modules
pub use crate::aead_cipher::*;
pub use crate::cipher::*;
pub use crate::errors::*;
pub use crate::key::*;
pub use crate::prf::*;
pub use crate::prg::*;
pub use crate::rcprf::*;
pub use crate::serialization::*;
pub use crate::utils::*;
