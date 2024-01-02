// Copyright (c) 2022-2024 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    rustdoc::broken_intra_doc_links
)]

use mc_sgx_core_sys_types::sgx_isv_svn_t;
use mc_sgx_dcap_sys_types::{quote3_error_t, sgx_ql_qe_report_info_t, sgx_ql_qv_result_t, time_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
