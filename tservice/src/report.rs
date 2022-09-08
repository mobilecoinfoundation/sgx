// Copyright (c) 2022 The MobileCoin Foundation
//! Functions used for creating and verifying reports inside of an enclave

use core::ptr;
use mc_sgx_core_sys_types::sgx_report_t;
use mc_sgx_core_types::{ReportData, Result, TargetInfo};
use mc_sgx_util::ResultInto;

/// Report operations that can be performed inside of an enclave
pub trait Report {
    /// Creates a report for the current enclave.
    ///
    /// # Arguments
    /// * `target_info` - The information for the target enclave which will
    ///   cryptographically verify the report.  See [`Report::verify_report()`].
    /// * `report_data` - Report data used to communicate between enclaves
    fn create_report(
        target_info: &TargetInfo,
        report_data: Option<&ReportData>,
    ) -> Result<mc_sgx_core_types::Report> {
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

    /// Verify an enclave report
    ///
    /// Ok means that the input report was generated using a [`TargetInfo`]
    /// that matches the one for the enclave making this call.
    ///
    /// # Arguments
    /// * `report` - The report to verify
    fn verify_report(report: &mc_sgx_core_types::Report) -> Result<()> {
        unsafe { mc_sgx_tservice_sys::sgx_verify_report(report.as_ref()) }.into_result()?;
        Ok(())
    }
}
