// Copyright (c) 2022 The MobileCoin Foundation

use mc_sgx_dcap_sys::{
    quote3_error_t, sgx_ql_qv_result_t, sgx_qv_verify_quote
};
use std::ptr;
use crate::{Error, Quote};

pub trait Verify {
    fn verify(&self) -> Result<(), Error>;
}

impl Verify for Quote {
    fn verify(&self) -> Result<(), Error> {
        // time_t -> pub type __time_t = ::std::os::raw::c_long;
        let mut quote: Vec<u8> = vec![0; 8];
        let mut expiration_status = 1;
        let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
        let result = unsafe { sgx_qv_verify_quote(quote.as_mut_ptr(), quote.len() as u32, ptr::null(),  0, &mut expiration_status, &mut quote_verification_result, ptr::null_mut(), 0, ptr::null_mut()) };
        match result {
            quote3_error_t::SGX_QL_SUCCESS => Ok(()),
            x => Err(Error::SgxStatus(x)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mc_sgx_dcap_sys::{
        quote3_error_t, sgx_qe_set_enclave_load_policy, sgx_ql_request_policy_t,
    };
    use mc_sgx_urts::{sgx_status_t, Enclave, EnclaveBuilder};
    use std::mem::MaybeUninit;
    use std::ptr;
    use test_enclave::{ecall_create_report, ENCLAVE};

    #[test]
    fn verify_quote() {
        let quote = Quote{ quote: vec![0] };
        let result = quote.verify();
        assert!(result.is_err());
    }
}
