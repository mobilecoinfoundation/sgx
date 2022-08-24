// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![feature(core_intrinsics)]

extern crate alloc;

mod attributes;
mod error;
mod key_request;
mod macros;

pub use crate::{
    attributes::{Attributes, MiscellaneousAttribute, MiscellaneousSelect},
    error::{Error, FfiError},
    key_request::{CpuSvn, KeyRequest},
};
