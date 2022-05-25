// Copyright (c) 2022 The MobileCoin Foundation
//! Rust wrappers for DCAP (Data Center Attestation Primitives) quote
//! verification

use mc_sgx_dcap_sys::{sgx_qv_set_enclave_load_policy};

#[cfg(test)]
mod tests {
    use super::*;
    use mc_sgx_dcap_sys::{quote3_error_t, sgx_ql_request_policy_t};

    #[test]
    fn verify_an_enclave() {
        let result = unsafe{ sgx_qv_set_enclave_load_policy(sgx_ql_request_policy_t::SGX_QL_DEFAULT) };
        assert_eq!(result, quote3_error_t::SGX_QL_SUCCESS);
    }
}
