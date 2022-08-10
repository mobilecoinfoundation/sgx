// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI bindings for the untrusted side of the Intel SGX SDK
use cargo_emit::{rustc_link_lib, rustc_link_search};

const URTS_FUNCTIONS: &[&str] = &[
    "sgx_create_enclave",
    "sgx_create_enclave_ex",
    "sgx_create_enclave_from_buffer_ex",
    "sgx_create_encrypted_enclave",
    "sgx_destroy_enclave",
    "sgx_get_target_info",
];

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let sgx_suffix = mc_sgx_core_build::sgx_library_suffix();
    rustc_link_lib!(&format!("sgx_urts{}", sgx_suffix));
    rustc_link_lib!(&format!("sgx_launch{}", sgx_suffix));
    rustc_link_search!(&format!("{}/lib64", sgx_library_path));

    let mut builder = mc_sgx_core_build::sgx_builder()
        .header_contents("urts.h", "#include <sgx_urts.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path));

    for f in URTS_FUNCTIONS {
        builder = builder.allowlist_function(f);
    }

    let out_path = mc_sgx_core_build::build_output_path();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
