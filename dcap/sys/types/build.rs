// Copyright (c) 2022-2025 The MobileCoin Foundation
//! Builds the FFI type bindings for the dcap libraries of the Intel
//! SGX SDK

use mc_sgx_core_build::SgxParseCallbacks;

const DCAP_TYPES: &[&str] = &[
    "_quote3_error_t",
    "_sgx_ql_qe3_id_t",
    "_sgx_ql_config_t",
    "_sgx_ql_config_version_t",
    "_sgx_ql_pck_cert_id_t",
    "_sgx_ql_qve_collateral_param_t",
    "_sgx_ql_qve_collateral_t",
    "_sgx_ql_log_level_t",
    "_sgx_prod_type_t",
    "sgx_ql_logging_callback_t",
    "_sgx_pce_error_t",
    "_sgx_ql_request_policy",
    "_sgx_pce_info_t",
    "_sgx_ql_att_key_id_param_t",
    "_sgx_ql_att_id_list_t",
    "_sgx_ql_qe_report_info_t",
    "sgx_ql_attestation_algorithm_id_t",
    "sgx_ql_cert_key_type_t",
    "_sgx_ql_att_key_id_list_header_t",
    "_sgx_ql_ppid_cleartext_cert_info_t",
    "_sgx_ql_ppid_rsa2048_encrypted_cert_info_t",
    "_sgx_ql_ppid_rsa3072_encrypted_cert_info_t",
    "_sgx_ql_auth_data_t",
    "_sgx_ql_certification_data_t",
    "_sgx_ql_ecdsa_sig_data_t",
    "_sgx_quote_header_t",
    "_sgx_quote3_t",
    "_sgx_ql_qv_result_t",
    "_pck_cert_flag_enum_t",
    "_sgx_ql_qv_supplemental_t",
];

fn main() {
    let callback = SgxParseCallbacks::default()
        .enum_types([
            "quote3_error_t",
            "sgx_ql_config_version_t",
            "sgx_ql_log_level_t",
            "sgx_prod_type_t",
            "sgx_pce_error_t",
            "sgx_ql_request_policy_t",
            "sgx_ql_attestation_algorithm_id_t",
            "sgx_ql_cert_key_type_t",
            "sgx_ql_qv_result_t",
            "pck_cert_flag_enum_t",
        ])
        .derive_copy([
            "quote3_error_t",
            "sgx_ql_pck_cert_id_t",
            "sgx_ql_config_t",
            "sgx_pce_info_t",
            "sgx_ql_att_key_id_list_header_t",
            "sgx_quote_header_t",
            "sgx_ql_qe_report_info_t",
            "sgx_ql_ppid_cleartext_cert_info_t",
            "sgx_ql_ppid_rsa2048_encrypted_cert_info_t",
            "sgx_ql_ppid_rsa3072_encrypted_cert_info_t",
        ])
        .dynamically_sized_types([
            "sgx_ql_auth_data_t",
            "sgx_ql_certification_data_t",
            "sgx_ql_ecdsa_sig_data_t",
            "sgx_quote3_t",
            "sgx_ql_att_key_id_param_t",
            "sgx_ql_att_id_list_t",
        ])
        .derive_default(["sgx_ql_qe_report_info_t"]);
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .parse_callbacks(Box::new(callback))
        .blocklist_function("*");

    for t in DCAP_TYPES {
        builder = builder.allowlist_type(t);
    }

    let out_path = mc_sgx_core_build::build_output_dir();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
