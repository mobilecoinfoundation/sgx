// Copyright (c) 2022 MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations)]

mod quote_enclave;
mod verify;

use mc_sgx_dcap_types::Quote3Error;
pub use quote_enclave::{LoadPolicyInitializer, PathInitializer};
pub use verify::supplemental_data_size;

/// Errors interacting with quote verification library functions
#[derive(Clone, Debug, displaydoc::Display, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Error {
    /// Paths have already been initialized
    PathsInitialized,
    /// Error from SGX quoting library function: {0}
    Sgx(Quote3Error),
    /// Failed to convert a path to a string.  Path {0}
    PathStringConversion(String),
    /// Path does not exist
    PathDoesNotExist(String),
    /// Path length is longer than the 259 character bytes allowed
    PathLengthTooLong(String),
    /// The quote verification enclave load policy has already been initialized
    LoadPolicyInitialized,
}

impl From<Quote3Error> for Error {
    fn from(src: Quote3Error) -> Self {
        Self::Sgx(src)
    }
}
