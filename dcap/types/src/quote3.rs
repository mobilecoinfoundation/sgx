// Copyright (c) 2022 The MobileCoin Foundation

//! This module provides types related to Quote v3

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Quote version 3
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Quote3<T> {
    bytes: T,
}

impl<'a> From<&'a [u8]> for Quote3<&'a [u8]> {
    fn from(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

#[cfg(feature = "alloc")]
impl From<Vec<u8>> for Quote3<Vec<u8>> {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    #[cfg(feature = "alloc")]
    use std::vec;

    use super::*;

    #[test]
    fn quote_from_slice() {
        let bytes = [4u8; 6].as_slice();
        let quote: Quote3<&[u8]> = bytes.into();
        assert_eq!(quote.bytes, bytes);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn quote_from_vec() {
        let bytes = vec![4u8; 6];
        let quote: Quote3<Vec<u8>> = bytes.clone().into();
        assert_eq!(quote.bytes, bytes);
    }
}
