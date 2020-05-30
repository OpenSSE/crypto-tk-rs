//! Utility functions

use num_traits::PrimInt;
use std::convert::From;
use std::ops::{Add, Div, Sub};

/// Compute ceil(x/y) when x and y are integer-like types
///
/// # Example
///
/// ```
/// # extern crate crypto_tk_rs;
/// use crypto_tk_rs::int_ceil_div;
///
/// assert_eq!(int_ceil_div(24,3),8);
/// assert_eq!(int_ceil_div(25,3),9);
/// ```
pub fn int_ceil_div<T>(x: T, y: T) -> T
where
    T: Sub<Output = T> + Add<Output = T> + Div<Output = T> + From<u8> + PrimInt,
{
    let one_1: T = std::convert::From::from(1u8);
    let one_2: T = std::convert::From::from(1u8);
    one_1 + ((x - one_2) / y)
}
