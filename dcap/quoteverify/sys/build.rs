// Copyright (c) 2022-2024 The MobileCoin Foundation
//! Builds the FFI function bindings for dcap quoteverify library of the Intel
//! SGX SDK

const DCAP_QL_FUNCTIONS: &[&str] = &[
    "sgx_qv_free_qve_identity",
    "sgx_qv_get_quote_supplemental_data_size",
    "sgx_qv_get_qve_identity",
    "sgx_qv_set_enclave_load_policy",
    "sgx_qv_set_path",
    "sgx_qv_verify_quote",
    "tee_qv_get_collateral",
    "tee_qv_free_collateral",
];

fn main() {
    cargo_emit::rustc_link_lib!("dylib=sgx_dcap_quoteverify");

    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .blocklist_type("*");

    for f in DCAP_QL_FUNCTIONS {
        builder = builder.allowlist_function(f);
    }

    let out_path = mc_sgx_core_build::build_output_dir();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
