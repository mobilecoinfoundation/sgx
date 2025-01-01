// Copyright (c) 2022-2025 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations)]

mod collateral;
mod quote_enclave;
mod verify;

pub use collateral::Collateral;
use mc_sgx_dcap_types::{CollateralError, QlError};
pub use quote_enclave::{LoadPolicyInitializer, PathInitializer};
pub use verify::supplemental_data_size;

/// Errors interacting with quote verification library functions
#[derive(Clone, Debug, displaydoc::Display, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Paths have already been initialized
    PathsInitialized,
    /// Error from SGX quoting library function: {0}
    QuoteLibrary(QlError),
    /// Failed to convert a path to a string.  Path {0}
    PathStringConversion(String),
    /// Path does not exist
    PathDoesNotExist(String),
    /// Path length is longer than the 259 character bytes allowed
    PathLengthTooLong(String),
    /// The quote verification enclave load policy has already been initialized
    LoadPolicyInitialized,
    /// Collateral data size is too small: should be at least {0}, got {1}
    CollateralSizeTooSmall(u32, u32),
    /// Error converting C data to rust Collateral type {0}
    CollateralConversion(CollateralError),
}

impl From<QlError> for Error {
    fn from(src: QlError) -> Self {
        Self::QuoteLibrary(src)
    }
}

impl From<CollateralError> for Error {
    fn from(src: CollateralError) -> Self {
        Self::CollateralConversion(src)
    }
}
