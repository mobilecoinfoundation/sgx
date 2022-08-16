// Copyright (c) 2022 The MobileCoin Foundation

//! Rust wrappers for SGX types

#![no_std]

extern crate alloc;

mod key_id;
mod traits;

pub use crate::key_id::KeyId;
