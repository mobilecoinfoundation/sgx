// Copyright (c) 2022-2023 The MobileCoin Foundation
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

/// The test enclave as bytes.
pub static ENCLAVE: &'static [u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/libenclave.signed.so"));
pub static ENCLAVE_KSS: &'static [u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/libenclave_kss.signed.so"));
pub static ENCLAVE_PCL: &'static [u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/libenclave_pcl.signed.so"));
pub static ENCLAVE_PCL_KEY: &'static [u8] = include_bytes!("pcl_key.bin");

use mc_sgx_core_sys_types::sgx_status_t;
use mc_sgx_urts_sys_types::sgx_enclave_id_t;
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
