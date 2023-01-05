// Copyright (c) 2022-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

/// Module used to assist unit tests that utilize the [`Sealed`] type
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

mod seal;

pub use crate::seal::Sealed;
