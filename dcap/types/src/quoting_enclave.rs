// Copyright (c) 2022-2024 The MobileCoin Foundation

//! Types specific to the quoting enclave

use mc_sgx_core_types::{impl_newtype, QuoteNonce, Report, TargetInfo};
use mc_sgx_dcap_sys_types::sgx_ql_qe_report_info_t;

/// Report info for the Quoting Enclave
#[repr(transparent)]
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct ReportInfo(sgx_ql_qe_report_info_t);

impl_newtype! {
    ReportInfo, sgx_ql_qe_report_info_t;
}

impl ReportInfo {
    /// The report of the quoting enclave
    pub fn report(&self) -> Report {
        self.0.qe_report.into()
    }

    /// The target info of the application enclave
    pub fn target_info(&self) -> TargetInfo {
        self.0.app_enclave_target_info.into()
    }

    /// The nonce
    pub fn nonce(&self) -> QuoteNonce {
        self.0.nonce.into()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_core_sys_types::{sgx_quote_nonce_t, sgx_report_t, sgx_target_info_t};

    #[test]
    fn default_report_info() {
        let info = ReportInfo::default();
        assert_eq!(info.report(), Report::default());
        assert_eq!(info.target_info(), TargetInfo::default());
        assert_eq!(info.nonce(), QuoteNonce::default());
    }

    #[test]
    fn from_report_info_t() {
        let mut report = sgx_report_t::default();
        report.body.cpu_svn.svn[0] = 1;
        let mut target_info = sgx_target_info_t::default();
        target_info.mr_enclave.m[0] = 2;
        let mut nonce = sgx_quote_nonce_t::default();
        nonce.rand[0] = 3;
        let info = sgx_ql_qe_report_info_t {
            qe_report: report,
            app_enclave_target_info: target_info,
            nonce,
        };

        let info: ReportInfo = info.into();

        assert_eq!(info.report(), report.into());
        assert_eq!(info.target_info(), target_info.into());
        assert_eq!(info.nonce(), nonce.into());
    }
}
