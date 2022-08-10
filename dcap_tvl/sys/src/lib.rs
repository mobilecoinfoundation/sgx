// Copyright (c) 2022 The MobileCoin Foundation
//! FFI functions for the SGX SDK DCAP tvl library.

#![no_std]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

use mc_sgx_core_sys_types::sgx_isv_svn_t;
use mc_sgx_dcap_ql_sys_types::quote3_error_t;
use mc_sgx_dcap_quoteverify_sys_types::{sgx_ql_qe_report_info_t, sgx_ql_qv_result_t, time_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
