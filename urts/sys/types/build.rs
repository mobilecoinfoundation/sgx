// Copyright (c) 2022-2025 The MobileCoin Foundation

//! Builds the FFI type bindings for the untrusted side of the Intel SGX SDK
use mc_sgx_core_build::SgxParseCallbacks;

const URTS_TYPES: &[&str] = &[
    "sgx_enclave_id_t",
    "sgx_launch_token_t",
    "_sgx_misc_attribute_t",
    "_sgx_kss_config_t",
];

const URTS_CONSTANTS: &[&str] = &[
    "SGX_CREATE_ENCLAVE_EX_PCL_BIT_IDX",
    "SGX_CREATE_ENCLAVE_EX_KSS_BIT_IDX",
    "SGX_CREATE_ENCLAVE_EX_PCL",
    "SGX_CREATE_ENCLAVE_EX_KSS",
    "MAX_EX_FEATURES_COUNT",
];

fn main() {
    let callback = SgxParseCallbacks::default().derive_copy(["sgx_kss_config_t"]);
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .parse_callbacks(Box::new(callback));

    for t in URTS_TYPES {
        builder = builder.allowlist_type(t);
    }

    for c in URTS_CONSTANTS {
        builder = builder.allowlist_var(c);
    }

    let out_path = mc_sgx_core_build::build_output_dir();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
