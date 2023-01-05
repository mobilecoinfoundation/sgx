// Copyright (c) 2022-2023 The MobileCoin Foundation

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
    error::{Error, FfiError},
    key_request::{KeyName, KeyPolicy, KeyRequest, KeyRequestBuilder},
    measurement::{Measurement, MrEnclave, MrSigner},
    quote::QuoteNonce,
    report::{Report, ReportBody, ReportData},
    svn::{ConfigSvn, CpuSvn, IsvSvn},
    target_info::TargetInfo,
};

// For targets that don't have a random number source we force it to always
// fail.
// Per https://docs.rs/getrandom/latest/getrandom/macro.register_custom_getrandom.html
// this function will *only* be used if getrandom doesn't know of a native
// secure spng
#[cfg(target_os = "none")]
use getrandom::register_custom_getrandom;

#[cfg(target_os = "none")]
register_custom_getrandom!(always_fail);

#[cfg(target_os = "none")]
fn always_fail(_buf: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
