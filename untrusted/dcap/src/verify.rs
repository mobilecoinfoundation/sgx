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
        let quote = self.quote.as_ptr();
        let quote_length = self.quote.len() as u32;
        let mut expiration_status = 1;
        let mut quote_verification_result = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_UNSPECIFIED;
        let result = unsafe { sgx_qv_verify_quote(quote, quote_length, ptr::null(),  1, &mut expiration_status, &mut quote_verification_result, ptr::null_mut(), 0, ptr::null_mut()) };
        match result {
            quote3_error_t::SGX_QL_SUCCESS => {
                match expiration_status {
                    0 => Ok(()),
                    _ => Err(Error::CollateralExpired),

                }
            },
            x => Err(Error::SgxStatus(x)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static VALID_QUOTE: &[u8] = include_bytes!("../../test_enclave/data/collateral_expired.dat");

    #[test]
    fn verify_results_in_unsupported_format_when_empty_quote() {
        // QUOTE_MIN_SIZE is 1020, so just round to a power of 2
        let quote = Quote{ quote: vec![0; 1024] };
        let result = quote.verify();
        assert_eq!(result, Err(Error::SgxStatus(quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED)));
    }

    #[test]
    fn verify_results_succeeds_for_good_quote() {
        let quote = Quote{ quote: VALID_QUOTE.to_vec() };
        let result = quote.verify();
        assert_eq!(result, Err(Error::CollateralExpired));
    }
}
