// Copyright (c) 2022-2025 The MobileCoin Foundation
//! Functions used for creating and verifying reports inside of an enclave

use core::ptr;
use mc_sgx_core_sys_types::sgx_report_t;
use mc_sgx_core_types::{ReportData, TargetInfo};
use mc_sgx_util::ResultInto;

pub type Result<T> = ::core::result::Result<T, mc_sgx_core_types::Error>;

/// Report operations that can be performed inside of an enclave
pub trait Report: Sized {
    /// Creates a report for the current enclave.
    ///
    /// # Arguments
    /// * `target_info` - The information for the target enclave which will
    ///   cryptographically verify the report.  See [`Report::verify()`].
    /// * `report_data` - Report data used to communicate between enclaves
    fn new(target_info: &TargetInfo, report_data: Option<&ReportData>) -> Result<Self>;

    /// Verify an enclave report
    ///
    /// Ok means that the report was generated using a [`TargetInfo`] that
    /// matches the one for the enclave making this call.
    fn verify(&self) -> Result<()>;
}

impl Report for mc_sgx_core_types::Report {
    fn new(target_info: &TargetInfo, report_data: Option<&ReportData>) -> Result<Self> {
        let mut report = sgx_report_t::default();
        unsafe {
            mc_sgx_tservice_sys::sgx_create_report(
                target_info.as_ref(),
                report_data.map_or_else(ptr::null, |data| data.as_ref()),
                &mut report,
            )
        }
        .into_result()?;
        Ok(report.into())
    }

    fn verify(&self) -> Result<()> {
        unsafe { mc_sgx_tservice_sys::sgx_verify_report(self.as_ref()) }.into_result()?;
        Ok(())
    }
}
