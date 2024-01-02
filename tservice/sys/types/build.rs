// Copyright (c) 2022-2024 The MobileCoin Foundation
//! Builds the FFI type bindings for tservice, (trusted service) of the Intel
//! SGX SDK

use mc_sgx_core_build::SgxParseCallbacks;

const SERVICE_TYPES: &[&str] = &[
    "align_req_t",
    "_aes_gcm_data_t",
    "_sealed_data_t",
    "_sgx_dh_msg1_t",
    "_sgx_dh_msg2_t",
    "_sgx_dh_msg3_body_t",
    "_sgx_dh_msg3_t",
    "_sgx_dh_session_enclave_identity_t",
    "_sgx_dh_session_role_t",
    "_sgx_dh_session_t",
    "_sgx_report2_mac_struct_t",
    "_sgx_report2_t",
    "_tee_cpu_svn_t",
    "_tee_measurement_t",
    "_tee_report_data_t",
    "_tee_attributes_t",
    "_tee_report_type_t",
    "tee_mac_t",
];

const SERVICE_CONSTS: &[&str] = &["SGX_DH_SESSION_DATA_SIZE"];

fn main() {
    let callback = SgxParseCallbacks::default()
        .enum_types(["sgx_dh_session_role_t"])
        .derive_copy([
            "sgx_dh_msg1_t",
            "sgx_dh_msg2_t",
            "sgx_dh_session_enclave_identity_t",
            "tee_attributes_t",
        ])
        .dynamically_sized_types([
            "sgx_dh_msg3_body_t",
            "sgx_aes_gcm_data_t",
            "sgx_dh_msg3_t",
            "sgx_sealed_data_t",
        ])
        .derive_default(["sgx_sealed_data_t", "sgx_aes_gcm_data_t"]);
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .parse_callbacks(Box::new(callback))
        .blocklist_function("*");

    for t in SERVICE_TYPES {
        builder = builder.allowlist_type(t);
    }

    for c in SERVICE_CONSTS.iter() {
        builder = builder.allowlist_var(c)
    }

    let out_path = mc_sgx_core_build::build_output_dir();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
