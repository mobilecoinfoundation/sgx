// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

mod attributes;
mod config_id;
mod error;
mod key_request;
mod macros;
mod measurement;
mod report;
mod svn;
mod target_info;

pub use crate::{
    attributes::{Attributes, MiscellaneousAttribute, MiscellaneousSelect},
    config_id::ConfigId,
    error::{Error, FfiError, Result},
    key_request::{KeyName, KeyPolicy, KeyRequest, KeyRequestBuilder},
    measurement::{Measurement, MrEnclave, MrSigner},
    report::ReportBody,
    svn::{ConfigSvn, CpuSvn, IsvSvn},
    target_info::TargetInfo,
};
