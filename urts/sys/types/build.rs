// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI type bindings for the untrusted side of the Intel SGX SDK
use std::{env, path::PathBuf};

const URTS_TYPES: &[&str] = &[
    "sgx_enclave_id_t",
    "sgx_launch_token_t",
    "_sgx_misc_attribute_t",
];

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header_contents("urts_types.h", "#include <sgx_urts.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path));

    for t in URTS_TYPES {
        builder = builder.allowlist_type(t);
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
