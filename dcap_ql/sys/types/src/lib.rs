// Copyright (c) 2022 The MobileCoin Foundation
//! Rust FFI types for the SGX SDK DCAP ql library.

#![no_std]
#![allow(
    clippy::missing_safety_doc,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]

use mc_sgx_core_sys_types::{sgx_cpu_svn_t, sgx_isv_svn_t};
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
