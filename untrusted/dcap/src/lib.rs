// Copyright (c) 2022 The MobileCoin Foundation
//! Rust wrappers for DCAP (Data Center Attestation Primitives) quote
//! verification

use std::mem;
use std::mem::MaybeUninit;
use mc_sgx_dcap_sys::{sgx_qe_get_quote, sgx_qe_get_quote_size, sgx_qv_set_enclave_load_policy, quote3_error_t, sgx_target_info_t, sgx_qe_get_target_info, sgx_report_t};
use mc_sgx_urts::Enclave;

#[derive(Debug, PartialEq)]
pub enum Error {
    // An error provided from the SGX SDK
    SgxStatus(quote3_error_t),
}

impl From<mc_sgx_urts::Error> for Error {
    fn from(err: mc_sgx_urts::Error) -> Self {
        match err {
            mc_sgx_urts::Error::SgxStatus(x) => {
                //TODO re-think, these codes don't transfer 1:1
                let error_code = x.0;
                let quote3_error = quote3_error_t(error_code);
                Error::SgxStatus(quote3_error)
            },
            mc_sgx_urts::Error::NoReportFunction => Error::SgxStatus(quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT),
        }
    }
}
pub struct Quote {
    quote: Vec<u8>,
}

impl Quote {
    pub fn new(enclave: &Enclave) -> Result<Self, Error> {
        Self::load_in_proc_enclaves()?;
        // TODO need to have a common type instead of transmuting these
        let target_info = Self::get_target_info()?;
        let target_info = unsafe{ mem::transmute(target_info) };
        let report = enclave.create_report(Some(&target_info))?;
        let report = unsafe{ mem::transmute(report) };

        Self::get_quote(report)
    }

    fn load_in_proc_enclaves() -> Result<(), Error> {
        //TODO this should be guarded by a feature and this should only be done
        //  once, maybe lazy_static
        Ok(())
    }

    fn get_target_info() -> Result<sgx_target_info_t, Error> {
        let target_info = MaybeUninit::zeroed();
        let mut target_info = unsafe { target_info.assume_init() };
        let result = unsafe{ sgx_qe_get_target_info(&mut target_info) };
        match result {
            quote3_error_t::SGX_QL_SUCCESS => Ok(target_info),
            x => Err(Error::SgxStatus(x))
        }
    }

    fn get_quote(report: sgx_report_t) -> Result<Quote, Error> {
        let mut size = 0;
        let result = unsafe{ sgx_qe_get_quote_size(&mut size) };
        if result != quote3_error_t::SGX_QL_SUCCESS {
            return Err(Error::SgxStatus(result))
        }

        let mut quote: Vec<u8> = vec![0; size as usize];
        let result = unsafe{ sgx_qe_get_quote(&report, size, quote.as_mut_ptr()) };
        match result {
            quote3_error_t::SGX_QL_SUCCESS => Ok(Quote{quote}),
            x => Err(Error::SgxStatus(x))
        }
    }
}


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
