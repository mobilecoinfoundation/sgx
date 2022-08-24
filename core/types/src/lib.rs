// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
// Needed for ::core::intrinsics::discriminant_value() to get underlying value
// of an enum.  Used in `key_request.rs`
#![feature(core_intrinsics)]

extern crate alloc;

mod attributes;
mod error;
mod key_request;
mod macros;
mod svn;

pub use crate::{
    attributes::{Attributes, MiscellaneousAttribute, MiscellaneousSelect},
    error::{Error, FfiError},
    key_request::{KeyName, KeyPolicy, KeyRequest, KeyRequestBuilder},
    svn::{ConfigSvn, CpuSvn, IsvSvn},
};
