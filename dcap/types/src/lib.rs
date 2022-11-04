// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod quote3;
mod quoting_enclave;
mod request_policy;

pub use crate::{
    error::QlError, quote3::Quote3, quoting_enclave::ReportInfo, request_policy::RequestPolicy,
};

// TODO:
//
// "_sgx_ql_qe3_id_t",
// "_sgx_ql_config_t",
// "_sgx_ql_config_version_t",
// "_sgx_ql_pck_cert_id_t",
// "_sgx_ql_qve_collateral_param_t",
// "_sgx_ql_qve_collateral_t",
// "_sgx_ql_log_level_t",
// "_sgx_prod_type_t",
// "sgx_ql_logging_callback_t",
// "_sgx_pce_error_t",
// "_sgx_ql_request_policy",
// "_sgx_pce_info_t",
// "_sgx_ql_att_key_id_param_t",
// "_sgx_ql_att_id_list_t",
// "sgx_ql_attestation_algorithm_id_t",
// "sgx_ql_cert_key_type_t",
// "_sgx_ql_att_key_id_list_header_t",
// "_sgx_ql_ppid_cleartext_cert_info_t",
// "_sgx_ql_ppid_rsa2048_encrypted_cert_info_t",
// "_sgx_ql_ppid_rsa3072_encrypted_cert_info_t",
// "_sgx_ql_auth_data_t",
// "_sgx_ql_certification_data_t",
// "_sgx_ql_ecdsa_sig_data_t",
// "_sgx_quote_header_t",
// "_sgx_quote3_t",
// "_sgx_ql_qv_result_t",
// "_pck_cert_flag_enum_t",
// "_sgx_ql_qv_supplemental_t",
