// Copyright (c) 2022 The MobileCoin Foundation
// See https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
//
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

pub use mc_sgx_dcap_sys_types::{sgx_qv_path_type_t, quote3_error_t, sgx_ql_qe_report_info_t, sgx_ql_qv_result_t, time_t, sgx_ql_qve_collateral_t, sgx_ql_request_policy_t, sgx_pce_error_t, sgx_isv_svn_t, sgx_report_t, sgx_cpu_svn_t, sgx_target_info_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
