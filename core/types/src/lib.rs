// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

mod attributes;
mod error;
mod key_request;
mod macros;
mod report;
mod svn;

pub use crate::{
    attributes::{Attributes, MiscellaneousAttribute, MiscellaneousSelect},
    error::{Error, FfiError, Result},
    key_request::{KeyName, KeyPolicy, KeyRequest, KeyRequestBuilder},
    report::{Measurement, ReportBody},
    svn::{ConfigSvn, CpuSvn, IsvSvn},
};
