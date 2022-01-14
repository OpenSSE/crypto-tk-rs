//! Utility functions

use std::convert::From;
use std::ops::{Add, Div, Sub};

/// Marker trait for primitive integers
pub trait PrimitiveInt {}

impl PrimitiveInt for u8 {}
impl PrimitiveInt for u16 {}
impl PrimitiveInt for u32 {}
impl PrimitiveInt for u64 {}
impl PrimitiveInt for u128 {}
impl PrimitiveInt for usize {}
impl PrimitiveInt for i8 {}
impl PrimitiveInt for i16 {}
impl PrimitiveInt for i32 {}
impl PrimitiveInt for i64 {}
impl PrimitiveInt for i128 {}
impl PrimitiveInt for isize {}

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
    T: Sub<Output = T>
        + Add<Output = T>
        + Div<Output = T>
        + From<u8>
        + PrimitiveInt,
{
    let one_1: T = std::convert::From::from(1u8);
    let one_2: T = std::convert::From::from(1u8);
    one_1 + ((x - one_2) / y)
}
