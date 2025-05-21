// Copyright (c) 2022-2025 The MobileCoin Foundation

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

impl Default for sgx_ql_qve_collateral_t {
    fn default() -> sgx_ql_qve_collateral_t {
        let version = sgx_ql_qve_collateral_t__bindgen_ty_1_t {
            version: Default::default(),
            __bindgen_anon_1: Default::default(),
            bindgen_union_field: 0,
        };

        sgx_ql_qve_collateral_t {
            __bindgen_anon_1: version,
            tee_type: 0,
            pck_crl_issuer_chain: core::ptr::null_mut(),
            pck_crl_issuer_chain_size: 0,
            root_ca_crl: core::ptr::null_mut(),
            root_ca_crl_size: 0,
            pck_crl: core::ptr::null_mut(),
            pck_crl_size: 0,
            tcb_info_issuer_chain: core::ptr::null_mut(),
            tcb_info_issuer_chain_size: 0,
            tcb_info: core::ptr::null_mut(),
            tcb_info_size: 0,
            qe_identity_issuer_chain: core::ptr::null_mut(),
            qe_identity_issuer_chain_size: 0,
            qe_identity: core::ptr::null_mut(),
            qe_identity_size: 0,
        }
    }
}
