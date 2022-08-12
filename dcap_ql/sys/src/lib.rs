// Copyright (c) 2022 The MobileCoin Foundation
//! FFI functions for the SGX SDK DCAP ql library.

#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]

use mc_sgx_core_sys_types::{sgx_report_t, sgx_target_info_t};
use mc_sgx_dcap_ql_sys_types::{quote3_error_t, sgx_ql_path_type_t, sgx_ql_request_policy_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
