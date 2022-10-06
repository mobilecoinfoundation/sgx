// Copyright (c) 2022 MobileCoin Foundation

//! Provides functionality for generating quotes
//!
//! This functionality requires HW SGX to work correctly otherwise all
//! functionality will return errors.

use mc_sgx_core_types::Report;
use mc_sgx_dcap_types::{Quote3, Quote3Error};
use mc_sgx_util::ResultInto;

/// Create a Quote3 from a Report
pub trait TryFromReport {
    /// Try to create a [`Quote3`] from the provided [`Report`]
    ///
    /// # Arguments
    /// * `report` - The report to build the quote from
    fn try_from_report(report: Report) -> Result<Quote3, Quote3Error> {
        let mut size = 0;
        unsafe { mc_sgx_dcap_ql_sys::sgx_qe_get_quote_size(&mut size) }.into_result()?;

        let mut quote = vec![0; size as usize];
        unsafe {
            mc_sgx_dcap_ql_sys::sgx_qe_get_quote(
                &report.into(),
                quote.len() as u32,
                quote.as_mut_ptr(),
            )
        }
        .into_result()?;
        Ok(quote.into())
    }
}

impl TryFromReport for Quote3 {}

#[cfg(all(test, not(feature = "sim")))]
mod test {
    use super::*;
    use crate::set_path;
    use crate::QeTargetInfo;
    use mc_sgx_core_types::TargetInfo;
    use mc_sgx_dcap_ql_types::PathKind::{
        IdEnclave, ProvisioningCertificateEnclave, QuotingEnclave,
    };

    #[test]
    fn get_quote() {
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
        // Target info must be gotten first in order to initialize sgx
        let _ = TargetInfo::for_quoting_enclave();
        let report = Report::default();
        assert_eq!(
            Quote3::try_from_report(report),
            Err(Quote3Error::InvalidReport)
        );
    }
}
