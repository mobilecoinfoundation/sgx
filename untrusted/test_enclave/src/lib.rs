// Copyright (c) 2022 The MobileCoin Foundation
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

/// The test enclave as bytes.
pub static ENCLAVE: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libenclave.signed.so"));

use mc_sgx_urts_sys_types::{sgx_enclave_id_t, sgx_status_t};
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
