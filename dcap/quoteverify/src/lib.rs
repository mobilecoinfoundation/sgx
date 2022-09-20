// Copyright (c) 2022 MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations)]

mod quote_enclave;

pub use quote_enclave::{load_policy, set_path};
