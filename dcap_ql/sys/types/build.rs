// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the dcap quote library of the Intel SGX SDK

use bindgen::callbacks::ParseCallbacks;

const DCAP_QL_TYPES: &[&str] = &[
    "_quote3_error_t",
    "_sgx_pce_error_t",
    "_sgx_pce_info_t",
    "_sgx_prod_type_t",
    "_sgx_ql_config_t",
    "_sgx_ql_config_version_t",
    "_sgx_ql_log_level_t",
    "_sgx_ql_qe3_id_t",
    "_sgx_ql_qe_report_info_t",
    "_sgx_ql_qve_collateral_param_t",
    "_sgx_ql_qve_collateral_t",
    "_sgx_ql_qve_collateral_t",
    "_sgx_ql_request_policy",
    "sgx_ql_logging_callback_t",
    "sgx_ql_path_type_t",
    "sgx_quote3_error_t",
];

/// ParseCallbacks to be used with [bindgen::Builder::parse_callbacks]
#[derive(Debug)]
pub struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        // The `_sgx_ql_request_policy` and `_quote_nonce` are outlier names
        // missing the trailing `_t`
        if name == "_sgx_ql_request_policy" {
            Some("sgx_ql_request_policy_t".to_owned())
        } else if name == "_quote_nonce" {
            Some("sgx_quote_nonce_t".to_owned())
        } else {
            mc_sgx_core_build::normalize_item_name(name)
        }
    }
}

fn main() {
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .blocklist_function("*")
        .parse_callbacks(Box::new(Callbacks));

    for t in DCAP_QL_TYPES {
        builder = builder.allowlist_type(t);
    }

    let out_path = mc_sgx_core_build::build_output_path();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
