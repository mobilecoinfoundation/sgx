// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the dcap quoteverify library of the Intel
//! SGX SDK

const DCAP_QUOTEVERIFY_TYPES: &[&str] = &["sgx_qv_path_type_t"];

fn main() {
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
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
