// Copyright (c) 2022 The MobileCoin Foundation
//! FFI functions for the SGX SDK trusted crypto library (tcrypto).

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

pub use mc_sgx_crypto_sys_types::{sgx_sha256_hash_t, sgx_status_t, size_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::convert::TryInto;

    #[test]
    fn run_sha256_1337() {
        let bytes: [u8; 4] = [1, 3, 3, 7];
        let mut hash: sgx_sha256_hash_t = Default::default();
        let result =
            unsafe { sgx_sha256_msg(bytes.as_ptr(), bytes.len().try_into().unwrap(), &mut hash) };
        assert_eq!(result, sgx_status_t::SGX_SUCCESS);

        let expected = {
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
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
            hasher.update(&bytes);
            hasher.finalize()
        };
        assert_eq!(hash, expected[..]);
    }
}
