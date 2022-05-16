// Copyright (c) 2022 The MobileCoin Foundation
// See https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_Enclave_Common_Loader_API_Reference.pdf

#![feature(core_ffi_c, c_size_t)]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

pub use core::ffi::c_size_t as size_t;
pub use mc_sgx_core_sys_types::sgx_status_t;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
