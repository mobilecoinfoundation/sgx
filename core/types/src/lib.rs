// Copyright (c) 2022 The MobileCoin Foundation

//! Rust wrappers for SGX types

#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

mod error;

pub use crate::error::FfiError;
