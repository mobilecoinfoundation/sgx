// Copyright (c) 2022 MobileCoin Foundation

//! Provides functionality for generating quotes
//!
//! This functionality requires HW SGX to work correctly otherwise all
//! functionality will return errors.

use mc_sgx_core_sys_types::sgx_target_info_t;
use mc_sgx_core_types::{Quote, Report, ReportData, TargetInfo};
use mc_sgx_dcap_types::Quote3Error;
use mc_sgx_util::ResultInto;

/// Functionality to create quotes.  Implementers should only need to implement
/// `report` as that will need to come from the application enclave.
pub trait QuoteGenerator {
    /// Report from an application enclave
    ///
    /// # Arguments
    /// * `target_info` - The information for the target enclave which will
    ///   cryptographically verify the report. This is usually from the
    ///   QE(Quoting Enclave).
    /// * `report_data` - Report data used to communicate between enclaves
    fn report(
        target_info: &TargetInfo,
        report_data: Option<&ReportData>,
    ) -> Result<Report, Quote3Error>;

    /// The target info of the QE(Quoting Enclave)
    fn target_info() -> Result<TargetInfo, Quote3Error> {
        let mut info = sgx_target_info_t::default();
        unsafe { mc_sgx_dcap_ql_sys::sgx_qe_get_target_info(&mut info) }.into_result()?;
        Ok(info.into())
    }

    /// A new quote for the instance
    ///
    /// # Arguments
    /// * `report_data` - Report data used to communicate between enclaves
    fn quote(report_data: Option<&ReportData>) -> Result<Quote<Vec<u8>>, Quote3Error> {
        //NB: The order of operations is important here.  Getting the target
        //    info will also internally initialize the quote library.  Calling
        //    `sgx_qe_get_quote_size()` prior to getting the target info will
        //    result in `AttestationKeyNotInitialized`.
        let report = Self::report(&Self::target_info()?, report_data)?;

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

#[cfg(all(test, not(feature = "sim")))]
mod test {
    use super::*;
    use crate::set_path;
    use mc_sgx_dcap_ql_types::PathKind::{
        IdEnclave, ProvisioningCertificateEnclave, QuotingEnclave,
    };

    pub struct LocalTester;

    impl QuoteGenerator for LocalTester {
        fn report(
            _target_info: &TargetInfo,
            _report_data: Option<&ReportData>,
        ) -> Result<Report, Quote3Error> {
            Ok(Report::default())
        }
    }

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
        let data = ReportData::default();
        assert_eq!(
            LocalTester::quote(Some(&data)),
            Err(Quote3Error::InvalidReport)
        );
    }
}
