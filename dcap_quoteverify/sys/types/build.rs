// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the dcap quoteverify library of the Intel
//! SGX SDK

const DCAP_QUOTEVERIFY_TYPES: &[&str] = &[
    "sgx_qv_path_type_t",
    "_sgx_ql_qv_result_t",
    "_sgx_ql_qv_supplemental_t",
    "_pck_cert_flag_enum_t",
    "_sgx_ql_att_key_id_param_t",
    "_sgx_ql_att_id_list_t",
    "_sgx_ql_qe_report_info_t",
    "_sgx_ql_att_key_id_list_header_t",
    "sgx_ql_attestation_algorithm_id_t",
    "sgx_ql_cert_key_type_t",
    "_sgx_ql_ppid_cleartext_cert_info_t",
    "_sgx_ql_ppid_rsa2048_encrypted_cert_info_t",
    "_sgx_ql_ppid_rsa3072_encrypted_cert_info_t",
    "_sgx_ql_auth_data_t",
    "_sgx_ql_certification_data_t",
    "_sgx_ql_ecdsa_sig_data_t",
    "_sgx_quote_header_t",
    "_sgx_quote3_t",
];

fn main() {
    let include_path = mc_sgx_core_build::sgx_include_path();
    cargo_emit::rerun_if_changed!(include_path);

    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}", include_path))
        .blocklist_function("*");

    for t in DCAP_QUOTEVERIFY_TYPES {
        builder = builder.allowlist_type(t);
    }

    let out_path = mc_sgx_core_build::build_output_path();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
