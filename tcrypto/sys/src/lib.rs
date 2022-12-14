// Copyright (c) 2022 The MobileCoin Foundation

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

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn run_sha256_1337() {
        let bytes: [u8; 4] = [1, 3, 3, 7];
        let mut hash: sgx_sha256_hash_t = Default::default();
        let result =
            unsafe { sgx_sha256_msg(bytes.as_ptr(), bytes.len().try_into().unwrap(), &mut hash) };
        assert_eq!(result, sgx_status_t::SGX_SUCCESS);

        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            hasher.finalize()
        };
        assert_eq!(hash, expected[..]);
    }

    #[test]
    fn run_sha256_42() {
        let bytes: [u8; 2] = [4, 2];
        let mut hash: sgx_sha256_hash_t = Default::default();
        let result =
            unsafe { sgx_sha256_msg(bytes.as_ptr(), bytes.len().try_into().unwrap(), &mut hash) };
        assert_eq!(result, sgx_status_t::SGX_SUCCESS);

        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(bytes);
            hasher.finalize()
        };
        assert_eq!(hash, expected[..]);
    }
}
