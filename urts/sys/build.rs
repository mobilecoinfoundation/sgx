// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Builds the FFI bindings for the untrusted side of the Intel SGX SDK

const URTS_FUNCTIONS: &[&str] = &[
    "sgx_create_enclave",
    "sgx_create_enclave_ex",
    "sgx_create_enclave_from_buffer_ex",
    "sgx_create_encrypted_enclave",
    "sgx_destroy_enclave",
    "sgx_get_target_info",
];

fn main() {
    let link_path = mc_sgx_core_build::sgx_library_string();
    cargo_emit::rustc_link_search!(link_path);

    let sgx_suffix = mc_sgx_core_build::sgx_library_suffix();
    cargo_emit::rustc_link_lib!(&format!("sgx_launch{sgx_suffix}"));
    cargo_emit::rustc_link_lib!(&format!("sgx_urts{sgx_suffix}"));
    cargo_emit::rustc_link_lib!(&format!("sgx_uae_service{sgx_suffix}"));

    let mut builder = mc_sgx_core_build::sgx_builder().header("wrapper.h");

    for f in URTS_FUNCTIONS {
        builder = builder.allowlist_function(f);
    }

    let out_path = mc_sgx_core_build::build_output_dir();

    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
