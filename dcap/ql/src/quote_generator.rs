// Copyright (c) 2022 MobileCoin Foundation

//! Provides functionality for generating quotes
//!
//! This functionality requires HW SGX to work correctly otherwise all
//! functionality will return errors.

use mc_sgx_core_sys_types::sgx_target_info_t;
use mc_sgx_core_types::TargetInfo;
use mc_sgx_dcap_types::Quote3Error;
use mc_sgx_util::ResultInto;

/// Provides behavior to generate quotes for enclaves
pub trait QuoteGenerator {
    /// The target info of the QE(Quoting Enclave)
    fn target_info() -> Result<TargetInfo, Quote3Error> {
        let mut info = sgx_target_info_t::default();
        unsafe { mc_sgx_dcap_ql_sys::sgx_qe_get_target_info(&mut info) }.into_result()?;
        Ok(info.into())
    }
}

#[cfg(all(test, not(feature = "sim")))]
mod test {
    use super::*;
    use crate::set_path;
    use mc_sgx_dcap_ql_types::PathKind::{
        IdEnclave, ProvisioningCertificateEnclave, QuotingEnclave,
    };

    pub struct LocalTester;

    impl QuoteGenerator for LocalTester {}

    #[test]
    fn getting_target_info() {
        set_path(
            ProvisioningCertificateEnclave,
            "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1",
        )
        .unwrap();
        set_path(
            QuotingEnclave,
            "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so.1",
        )
        .unwrap();
        set_path(
            IdEnclave,
            "/usr/lib/x86_64-linux-gnu/libsgx_id_enclave.signed.so.1",
        )
        .unwrap();
        assert!(LocalTester::target_info().is_ok());
    }
}
