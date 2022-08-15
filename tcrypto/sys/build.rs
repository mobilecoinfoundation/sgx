// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI function bindings for trusted crypto (tcrypto) of the
//! Intel SGX SDK

const CRYPTO_FUNCTIONS: &[&str] = &[
    "sgx_aes_ctr_decrypt",
    "sgx_aes_ctr_encrypt",
    "sgx_aes_gcm128_enc_get_mac",
    "sgx_aes_gcm128_enc_init",
    "sgx_aes_gcm128_enc_update",
    "sgx_aes_gcm_close",
    "sgx_calculate_ecdsa_priv_key",
    "sgx_cmac128_close",
    "sgx_cmac128_final",
    "sgx_cmac128_init",
    "sgx_cmac128_update",
    "sgx_create_rsa_key_pair",
    "sgx_create_rsa_priv1_key",
    "sgx_create_rsa_priv2_key",
    "sgx_create_rsa_pub1_key",
    "sgx_ecc256_calculate_pub_from_priv",
    "sgx_ecc256_check_point",
    "sgx_ecc256_close_context",
    "sgx_ecc256_compute_shared_dhkey",
    "sgx_ecc256_compute_shared_point",
    "sgx_ecc256_create_key_pair",
    "sgx_ecc256_open_context",
    "sgx_ecdsa_sign",
    "sgx_ecdsa_verify",
    "sgx_ecdsa_verify_hash",
    "sgx_free_rsa_key",
    "sgx_hmac256_close",
    "sgx_hmac256_final",
    "sgx_hmac256_init",
    "sgx_hmac256_update",
    "sgx_hmac_sha256_msg",
    "sgx_rijndael128GCM_decrypt",
    "sgx_rijndael128GCM_encrypt",
    "sgx_rijndael128_cmac_msg",
    "sgx_rsa3072_sign",
    "sgx_rsa3072_sign_ex",
    "sgx_rsa3072_verify",
    "sgx_rsa_priv_decrypt_sha256",
    "sgx_rsa_pub_encrypt_sha256",
    "sgx_sha1_close",
    "sgx_sha1_get_hash",
    "sgx_sha1_init",
    "sgx_sha1_msg",
    "sgx_sha1_update",
    "sgx_sha256_close",
    "sgx_sha256_get_hash",
    "sgx_sha256_init",
    "sgx_sha256_msg",
    "sgx_sha256_update",
    "sgx_sha384_close",
    "sgx_sha384_get_hash",
    "sgx_sha384_init",
    "sgx_sha384_msg",
    "sgx_sha384_update",
];

fn main() {
    let include_path = mc_sgx_core_build::sgx_include_string();
    cargo_emit::rerun_if_changed!(include_path);

    let link_path = mc_sgx_core_build::sgx_library_string();
    cargo_emit::rerun_if_changed!(link_path);
    cargo_emit::rustc_link_search!(link_path);
    cargo_emit::rustc_link_lib!("static=sgx_tcrypto");

    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}", include_path))
        .blocklist_type("*");

    for f in CRYPTO_FUNCTIONS {
        builder = builder.allowlist_function(f);
    }

    let out_path = mc_sgx_core_build::build_output_path();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
