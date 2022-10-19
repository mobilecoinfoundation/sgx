// Copyright (c) 2022 MobileCoin Foundation

//! Provides functionality for generating quote version 3 quotes
//!
//! This functionality requires HW SGX to work correctly otherwise all
//! functionality will return errors.

use crate::Error;
use mc_sgx_core_types::Report;
use mc_sgx_dcap_types::Quote3;
use mc_sgx_util::ResultInto;

/// Create a Quote3 from a Report
pub trait TryFromReport {
    /// Try to create a [`Quote3`] from the provided [`Report`]
    ///
    /// Note: This will initialize the [`PathInitializer`] and
    ///   [`LoadPolicyInitializer`] to the defaults if they have not been
    ///   initialized yet. Attempts to initialize [`PathInitializer`] or
    ///   [`LoadPolicyInitializer`] after calling this function will result in
    ///   an error.
    ///
    /// # Arguments
    /// * `report` - The report to build the quote from
    ///
    /// # Errors
    /// Will return an [`Error::Sgx`] if there is a failure from the SGX SDK
    fn try_from_report(report: Report) -> Result<Quote3<Vec<u8>>, Error> {
        crate::PathInitializer::ensure_initialized()?;
        crate::LoadPolicyInitializer::ensure_initialized()?;

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

impl TryFromReport for Quote3<Vec<u8>> {}

#[cfg(all(test, not(feature = "sim")))]
mod test {
    use super::*;
    use crate::QeTargetInfo;
    use mc_sgx_core_types::TargetInfo;
    use mc_sgx_dcap_types::Quote3Error;

    #[test]
    fn get_quote() {
        // Target info must be gotten first in order to initialize sgx
        let _ = TargetInfo::for_quoting_enclave();
        let report = Report::default();
        assert_eq!(
            Quote3::try_from_report(report),
            Err(Error::Sgx(Quote3Error::InvalidReport))
        );
    }
}
