// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod attestation_key;
mod attributes;
mod config_id;
mod error;
mod key_request;
mod macros;
mod measurement;
mod quote;
mod report;
mod svn;
mod target_info;

pub use crate::{
    attestation_key::{AttestationKeyId, ExtendedAttestationKeyId},
    attributes::{Attributes, MiscellaneousAttribute, MiscellaneousSelect},
    config_id::ConfigId,
    error::{Error, FfiError, Result},
    key_request::{KeyName, KeyPolicy, KeyRequest, KeyRequestBuilder},
    measurement::{Measurement, MrEnclave, MrSigner},
    report::{IsvProductId, ReportBody},
    svn::{ConfigSvn, CpuSvn, IsvSvn},
    target_info::TargetInfo,
};
