// Copyright (c) 2022 The MobileCoin Foundation

use crate::{Error, Quote};

pub trait Verify {
    fn verify(&self) -> Result<(), Error>;
}

impl Verify for Quote {
    fn verify(&self) -> Result<(), Error> {
        Ok(())
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
