// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI bindings for the untrusted side of the Intel SGX SDK

const URTS_FUNCTIONS: &[&str] = &[
    "sgx_create_enclave",
    "sgx_create_enclave_ex",
    "sgx_create_enclave_from_buffer_ex",
    "sgx_create_encrypted_enclave",
    "sgx_destroy_enclave",
    "sgx_get_target_info",
];

const URTS_CONSTANTS: &[&str] = &[
    "SGX_CREATE_ENCLAVE_EX_PCL_BIT_IDX",
    "SGX_CREATE_ENCLAVE_EX_KSS_BIT_IDX",
    "SGX_CREATE_ENCLAVE_EX_PCL",
    "SGX_CREATE_ENCLAVE_EX_KSS",
    "MAX_EX_FEATURES_COUNT",
];

fn main() {
    let link_path = mc_sgx_core_build::sgx_library_string();
    cargo_emit::rustc_link_search!(link_path);

    let sgx_suffix = mc_sgx_core_build::sgx_library_suffix();
    cargo_emit::rustc_link_lib!(&format!("sgx_launch{}", sgx_suffix));
    cargo_emit::rustc_link_lib!(&format!("sgx_urts{}", sgx_suffix));
    cargo_emit::rustc_link_lib!(&format!("sgx_uae_service{}", sgx_suffix));

    let mut builder = mc_sgx_core_build::sgx_builder().header("wrapper.h");

    for f in URTS_FUNCTIONS {
        builder = builder.allowlist_function(f);
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
