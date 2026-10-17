// Copyright (c) 2022-2025 The MobileCoin Foundation
//! Builds the FFI function bindings for dcap ql library of the Intel SGX SDK

const DCAP_QL_FUNCTIONS: &[&str] = &[
    "sgx_qe_cleanup_by_policy",
    "sgx_qe_get_quote",
    "sgx_qe_get_quote_size",
    "sgx_qe_get_target_info",
    "sgx_qe_set_enclave_load_policy",
    "sgx_ql_set_path",
];

fn main() {
    cargo_emit::rustc_link_lib!("dylib=sgx_dcap_ql");

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
