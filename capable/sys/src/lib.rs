// Copyright (c) 2022-2025 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![allow(non_camel_case_types)]

pub use mc_sgx_capable_sys_types::sgx_device_status_t;
pub use mc_sgx_core_sys_types::sgx_status_t;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
