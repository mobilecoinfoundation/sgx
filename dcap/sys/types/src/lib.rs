// Copyright (c) 2022-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![allow(
    clippy::missing_safety_doc,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_unsafe
)]

use mc_sgx_core_sys_types::{
    sgx_att_key_id_ext_t, sgx_cpu_svn_t, sgx_isv_svn_t, sgx_key_128bit_t, sgx_quote_nonce_t,
    sgx_report_body_t, sgx_report_t, sgx_target_info_t,
};

// time_t normally comes from libc, however libc doesn't have definitions for
// the sgx target so we explicitly define it here.
pub type time_t = i64;
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
