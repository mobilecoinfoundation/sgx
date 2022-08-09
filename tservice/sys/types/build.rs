// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for tservice, (trusted service) of the Intel
//! SGX SDK

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
    "_tee_cpu_svn_t",
    "_tee_measurement_t",
    "_tee_report_data_t",
    "_tee_report_type_t",
    "tee_mac_t",
];

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .blocklist_function("*");

    for t in SERVICE_TYPES {
        builder = builder.allowlist_type(t);
    }

    let out_path = mc_sgx_core_build::build_output_path();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
