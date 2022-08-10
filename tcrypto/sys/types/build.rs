// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the trusted crypto functions, (aes, rsa,
//! etc.), of the Intel SGX SDK

const CRYPTO_TYPES: &[&str] = &[
    "_rsa_params_t",
    "_sgx_ec256_dh_shared_t",
    "_sgx_ec256_private_t",
    "_sgx_ec256_public_t",
    "_sgx_ec256_signature_t",
    "_sgx_rsa3072_key_t",
    "_sgx_rsa3072_public_key_t",
    "sgx_aes_ctr_128bit_key_t",
    "sgx_aes_gcm_128bit_key_t",
    "sgx_aes_gcm_128bit_tag_t",
    "sgx_aes_state_handle_t",
    "sgx_cmac_128bit_key_t",
    "sgx_cmac_128bit_tag_t",
    "sgx_cmac_state_handle_t",
    "sgx_ec256_shared_point_t",
    "sgx_ecc_state_handle_t",
    "sgx_generic_ecresult_t",
    "sgx_hmac_state_handle_t",
    "sgx_hmac_256bit_key_t",
    "sgx_hmac_256bit_tag_t",
    "sgx_rsa3072_signature_t",
    "sgx_rsa_key_type_t",
    "sgx_rsa_result_t",
    "sgx_sha1_hash_t",
    "sgx_sha256_hash_t",
    "sgx_sha384_hash_t",
    "sgx_sha_state_handle_t",
];

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .blocklist_function("*");

    for t in CRYPTO_TYPES {
        builder = builder.allowlist_type(t);
    }

    let out_path = mc_sgx_core_build::build_output_path();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
