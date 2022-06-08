// Copyright (c) 2022 The MobileCoin Foundation
use mc_sgx_dcap_sys::quote3_error_t;

/// Errors generating quotes
#[derive(Debug, PartialEq)]
pub enum Error {
    /// An error provided from the SGX SDK
    SgxStatus(quote3_error_t),
    /// Quote verification succeeded, but the collateral used has expired
    CollateralExpired,
}

impl From<mc_sgx_urts::Error> for Error {
    fn from(err: mc_sgx_urts::Error) -> Self {
        match err {
            mc_sgx_urts::Error::SgxStatus(x) => {
                // TODO re-think, these codes don't transfer 1:1
                //  However SGX keeps the code separate by providing a mask on
                //  the upper bits of a 16 bit value per the below macro
                //  `#define SGX_???_ERROR(x) (0x0000?000|(x))`  The `?` changes
                //  based on where the error comes from
                let error_code = x.0;
                let quote3_error = quote3_error_t(error_code);
                Error::SgxStatus(quote3_error)
            }
            mc_sgx_urts::Error::NoReportFunction => {
                Error::SgxStatus(quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT)
            }
        }
    }
}
