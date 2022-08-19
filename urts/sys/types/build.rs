// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI type bindings for the untrusted side of the Intel SGX SDK
use mc_sgx_core_build::SgxParseCallbacks;

const URTS_TYPES: &[&str] = &[
    "sgx_enclave_id_t",
    "sgx_launch_token_t",
    "_sgx_misc_attribute_t",
    "_sgx_kss_config_t",
];

fn main() {
    let include_path = mc_sgx_core_build::sgx_include_string();
    cargo_emit::rerun_if_changed!(include_path);

    let callback = SgxParseCallbacks::new(["sgx_kss_config_t"].iter());
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}", include_path))
        .parse_callbacks(Box::new(callback));

    for t in URTS_TYPES {
        builder = builder.allowlist_type(t);
    }

    let out_path = mc_sgx_core_build::build_output_dir();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
