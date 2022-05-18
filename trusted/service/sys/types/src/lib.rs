// Copyright (c) 2022 The MobileCoin Foundation
//! FFI types for the SGX SDK trusted service library (tservice).

#![feature(core_ffi_c)]
// Nesting to work around clippy warnings, see
// https://github.com/rust-lang/rust-bindgen/issues/1470
#[allow(
    clippy::missing_safety_doc,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]

mod bindings {
    use mc_sgx_core_sys_types::{
        sgx_attributes_t, sgx_config_id_t, sgx_config_svn_t, sgx_isv_svn_t, sgx_isvext_prod_id_t,
        sgx_isvfamily_id_t, sgx_key_request_t, sgx_mac_t, sgx_misc_select_t, sgx_prod_id_t,
        sgx_report_body_t, sgx_report_t, sgx_target_info_t,
    };
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use bindings::*;
