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
    default_for_byte_struct, sgx_attributes_t, sgx_cpu_svn_t, sgx_isv_svn_t, sgx_key_request_t,
    sgx_measurement_t, sgx_misc_select_t, sgx_prod_id_t, sgx_report_t, sgx_target_info_t,
};
use mc_sgx_tcrypto_sys_types::sgx_ec256_public_t;
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

default_for_byte_struct! {
    sgx_dh_session_t, sgx_dh_session, SGX_DH_SESSION_DATA_SIZE;
}
