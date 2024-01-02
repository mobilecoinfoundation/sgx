// Copyright (c) 2022-2024 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![allow(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    rustdoc::broken_intra_doc_links
)]

use mc_sgx_core_sys_types::sgx_status_t;

pub use mc_sgx_tcrypto_sys_types::{
    sgx_aes_ctr_128bit_key_t, sgx_aes_gcm_128bit_key_t, sgx_aes_gcm_128bit_tag_t,
    sgx_aes_state_handle_t, sgx_cmac_128bit_key_t, sgx_cmac_128bit_tag_t, sgx_cmac_state_handle_t,
    sgx_ec256_dh_shared_t, sgx_ec256_private_t, sgx_ec256_public_t, sgx_ec256_signature_t,
    sgx_ecc_state_handle_t, sgx_hmac_state_handle_t, sgx_rsa3072_key_t, sgx_rsa3072_public_key_t,
    sgx_rsa3072_signature_t, sgx_rsa_key_type_t, sgx_rsa_result_t, sgx_sha1_hash_t,
    sgx_sha256_hash_t, sgx_sha384_hash_t, sgx_sha_state_handle_t,
};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
