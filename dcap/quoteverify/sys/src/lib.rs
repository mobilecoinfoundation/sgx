// Copyright (c) 2022-2024 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

use mc_sgx_dcap_quoteverify_sys_types::sgx_qv_path_type_t;
use mc_sgx_dcap_sys_types::{
    quote3_error_t, sgx_ql_qe_report_info_t, sgx_ql_qv_result_t, sgx_ql_qve_collateral_t,
    sgx_ql_request_policy_t, time_t,
};
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
