#![forbid(unsafe_code)]
#![warn(missing_docs)]
// #![cfg_attr(feature = "with-bench", feature(test))]

// Enable pedantic warnings...
#![warn(clippy::pedantic)]
// ... with exceptions
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
//# Wildcard imports are quite useful in order to keep imports concise.
#![allow(clippy::wildcard_imports)]
//# This might bad for a API's user standpoint, but in our case, it avoids
//# confusion.
#![allow(clippy::module_name_repetitions)]
//# Non ASCII identifiers might create security vulnerabilities. See the [Rust blog](https://blog.rust-lang.org/2021/11/01/cve-2021-42574.html)
//# for more details.
#![forbid(non_ascii_idents)]
//# Prevent memory leaks, unless well documented
#![deny(clippy::mem_forget)]
#![warn(clippy::todo)]
#![warn(clippy::unwrap_in_result)]
// // #![warn(clippy::restriction)]
// #![warn(clippy::expect_used)]
// #![warn(clippy::future_not_send)]
// #![warn(clippy::if_then_some_else_none)]
// // This lint unfortunately has too many false positives
// // #![warn(clippy::indexing_slicing)]
// #![warn(clippy::integer_arithmetic)]
// #![warn(clippy::cognitive_complexity)]
// #![warn(clippy::try_err)]
// #![warn(clippy::unimplemented)]
// #![warn(clippy::unwrap_used)]
// #![warn(clippy::use_debug)]
// #![warn(clippy::map_err_ignore)]

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
pub use crate::hash::*;
pub use crate::key::*;
pub use crate::prf::*;
pub use crate::prg::*;
pub use crate::rcprf::*;
pub use crate::serialization::*;
pub use crate::utils::*;
