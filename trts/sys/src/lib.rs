// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

pub use mc_sgx_core_sys_types::sgx_status_t;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
