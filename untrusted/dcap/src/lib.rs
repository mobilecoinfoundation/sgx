// Copyright (c) 2022 The MobileCoin Foundation
//! Rust wrappers for DCAP (Data Center Attestation Primitives) quote
//! verification

use mc_sgx_dcap_sys::{sgx_qv_set_enclave_load_policy};
use mc_sgx_urts::Enclave;

#[derive(Debug, PartialEq)]
pub enum Error {
    // An error provided from the SGX SDK
    SgxStatus(sgx_status_t),
}

pub struct Quote {
    quote: sgx_quote_t,
}

impl Quote {
    pub fn new(enclave: &Enclave) -> Result<Self, Error> {
        Self::load_in_proc_enclaves()?;
        let target_info = Self::get_target_info()?;

        // TODO not sure if the report should live here or on teh enclave,
        //  either way I think it should use a closure since there is no
        //  standardized ecall for it.
        let report = enclave.get_report(target_info)?;

        Self::get_quote(report)
    }

    fn load_in_proc_enclaves() -> Result<(), Error> {
        //TODO this should be guarded by a feature and this should only be done
        //  once, maybe lazy_static
        Ok(())
    }

    fn get_target_info() -> Result<sgx_target_info, Error> {
        let mut target_info: sgx_target_info = Default::default();
        let result = unsafe{ sgx_qe_get_target_info(&mut target_info) };
        match result {
            SGX_QL_SUCCESS => Ok(target_info),
            x => Err(Error::SgxStatus(x))
        }
    }

    fn get_quote(report: sgx_report_t) -> Result<sgx_quote_t, Error> {
        let mut size = 0;
        let result = unsafe{ sgx_qe_get_quote_size(&mut size) };
        if result != SGX_QL_SUCCESS {
            return Err(Error::SgxStatus(result))
        }

        let mut quote: Vec<u8> = vec![0; size];
        let result = unsafe{ sgx_qe_get_quote(&report, &size, quote_buffer.as_mut_ptr()) };
        match result {
            SGX_QL_SUCCESS => Ok(Quote{quote}),
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
