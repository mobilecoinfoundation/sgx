// Copyright (c) 2022 MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations)]

extern crate alloc;

mod quote3;
mod quote_enclave;

use mc_sgx_dcap_types::Quote3Error;
pub use quote3::TryFromReport;
pub use quote_enclave::{load_policy, PathInitializer, QeTargetInfo};

/// Errors interacting with quote library functions
#[derive(Clone, Debug, displaydoc::Display, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Error {
    /// Paths have already been initialized
    PathsInitialized,
    /// Error from SGX quoting library function: {0}
    Sgx(Quote3Error),
    /// Failed ot convert a path to a string.  Path {0}
    PathStringConversion(String),
}

impl From<Quote3Error> for Error {
    fn from(src: Quote3Error) -> Self {
        Self::Sgx(src)
    }
}
