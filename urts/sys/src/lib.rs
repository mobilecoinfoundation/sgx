// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![feature(c_size_t)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use core::ffi::c_size_t as size_t;
use mc_sgx_core_sys_types::{sgx_status_t, sgx_target_info_t};
use mc_sgx_urts_sys_types::{sgx_enclave_id_t, sgx_launch_token_t, sgx_misc_attribute_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
