// Copyright (c) 2022-2025 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
mod edger8r;
mod sign;

pub use crate::edger8r::Edger8r;
pub use crate::sign::SgxSign;
