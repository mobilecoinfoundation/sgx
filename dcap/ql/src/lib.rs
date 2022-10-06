// Copyright (c) 2022 MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations)]

extern crate alloc;

mod quote_enclave;
mod quote_generator;

pub use quote_enclave::{load_policy, set_path, QeTargetInfo};
pub use quote_generator::TryFromReport;
