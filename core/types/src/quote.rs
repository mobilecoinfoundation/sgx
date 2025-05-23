// Copyright (c) 2022-2024 The MobileCoin Foundation
//! Quote types

use crate::{
    attestation_key::QuoteSignatureKind, impl_display_for_bytestruct, impl_newtype,
    impl_newtype_for_bytestruct, report::Report, FfiError, IsvSvn, ReportBody, TargetInfo,
};
use mc_sgx_core_sys_types::{
    sgx_basename_t, sgx_epid_group_id_t, sgx_platform_info_t, sgx_qe_report_info_t,
    sgx_quote_nonce_t, sgx_quote_sign_type_t, sgx_update_info_bit_t, SGX_PLATFORM_INFO_SIZE,
};
use serde::{Deserialize, Serialize};

/// Quoting Enclave Report Info
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct QuotingEnclaveReportInfo(sgx_qe_report_info_t);

impl QuotingEnclaveReportInfo {
    /// The nonce from app enclave used to generate quote
    pub fn nonce(&self) -> QuoteNonce {
        self.0.nonce.into()
    }

    /// The target info of the app enclave
    pub fn app_enclave_target_info(&self) -> TargetInfo {
        self.0.app_enclave_target_info.into()
    }

    /// The report generated by the quoting enclave
    pub fn report(&self) -> Report {
        self.0.qe_report.into()
    }
}

impl_newtype! {
    QuotingEnclaveReportInfo, sgx_qe_report_info_t;
}

/// Platform Info
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct PlatformInfo(sgx_platform_info_t);

impl_newtype_for_bytestruct! {
    PlatformInfo, sgx_platform_info_t, SGX_PLATFORM_INFO_SIZE, platform_info;
}
impl_display_for_bytestruct!(PlatformInfo);

/// Update Info Bit
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct UpdateInfoBit(sgx_update_info_bit_t);

impl_newtype! {
    UpdateInfoBit, sgx_update_info_bit_t;
}

impl UpdateInfoBit {
    /// Returns if the ucode need updated
    pub fn ucode_needs_update(&self) -> bool {
        self.0.ucodeUpdate != 0
    }

    /// Returns if the csme firmware needs updated
    pub fn csme_firmware_needs_update(&self) -> bool {
        self.0.csmeFwUpdate != 0
    }

    /// Returns if the platform software needs updated
    pub fn platform_software_needs_update(&self) -> bool {
        self.0.pswUpdate != 0
    }
}

/// EPID Group ID
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct EpidGroupId(sgx_epid_group_id_t);

impl_newtype! {
    EpidGroupId, sgx_epid_group_id_t;
}

const BASENAME_SIZE: usize = 32;

/// Basename
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct Basename(sgx_basename_t);

impl_newtype_for_bytestruct! {
    Basename, sgx_basename_t, BASENAME_SIZE, name;
}
impl_display_for_bytestruct!(Basename);

const NONCE_SIZE: usize = 16;

/// Quote Nonce
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[repr(transparent)]
pub struct QuoteNonce(sgx_quote_nonce_t);

impl_newtype_for_bytestruct! {
    QuoteNonce, sgx_quote_nonce_t, NONCE_SIZE, rand;
}
impl_display_for_bytestruct!(QuoteNonce);

/// The raw bytes representing a quote.
///
/// Should not be used directly instead use [`Quote`].
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct RawQuote<'a> {
    bytes: &'a [u8],
}

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct Version(u16);

impl_newtype! {
    Version, u16;
}

pub trait BaseQuote {
    /// Provides access to the [`RawQuote`] to perform the common lookup
    /// operations on the basic quote type.
    fn _raw_quote(&self) -> &RawQuote;

    /// Version of the quote
    fn _version(&self) -> Version {
        let bytes = self._raw_quote().bytes[..2]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `version`");
        u16::from_le_bytes(bytes).into()
    }

    /// The signature type
    fn _signature_type(&self) -> Result<QuoteSignatureKind, FfiError> {
        let bytes = self._raw_quote().bytes[2..4]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `sign_type`");
        sgx_quote_sign_type_t(u16::from_le_bytes(bytes) as u32).try_into()
    }

    /// EPID group id
    fn _epid_group_id(&self) -> EpidGroupId {
        let bytes: [u8; 4] = self._raw_quote().bytes[4..8]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `epid_group_id`");
        bytes.into()
    }

    /// Quoting enclave (QE) SVN (Security Version Number)
    fn _quoting_enclave_svn(&self) -> IsvSvn {
        let bytes = self._raw_quote().bytes[8..10]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `qe_svn`");
        u16::from_le_bytes(bytes).into()
    }

    /// Provisioning certification enclave (PCE) SVN (Security Version Number)
    fn _provisioning_certification_enclave_svn(&self) -> IsvSvn {
        let bytes = self._raw_quote().bytes[10..12]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `pce_svn`");
        u16::from_le_bytes(bytes).into()
    }

    /// Extended EPID group id
    fn _extended_epid_group_id(&self) -> EpidGroupId {
        let bytes: [u8; 4] = self._raw_quote().bytes[12..16]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `xeid`");
        bytes.into()
    }

    /// Basename
    fn _basename(&self) -> Basename {
        let bytes: [u8; BASENAME_SIZE] = self._raw_quote().bytes[16..48]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `basename`");
        bytes.into()
    }

    /// Report body
    fn _report_body(&self) -> Result<ReportBody, FfiError> {
        self._raw_quote().bytes[48..432].try_into()
    }
}

impl<'a> From<&'a [u8]> for RawQuote<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

/// Quote
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Quote<'a>(RawQuote<'a>);

impl BaseQuote for Quote<'_> {
    fn _raw_quote(&self) -> &RawQuote {
        &self.0
    }
}

impl<'a> From<RawQuote<'a>> for Quote<'a> {
    fn from(raw: RawQuote<'a>) -> Self {
        Self(raw)
    }
}

impl<'a> From<&'a [u8]> for Quote<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self(bytes.into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::{mem, slice};
    use mc_sgx_core_sys_types::{sgx_quote_t, sgx_report_body_t, sgx_report_t, sgx_target_info_t};

    #[allow(unsafe_code)]
    fn quote_to_bytes(report: sgx_quote_t) -> [u8; mem::size_of::<sgx_quote_t>()] {
        // SAFETY: This is a test only function. The size of `quote` is used
        // for reinterpretation of `quote` into a byte slice. The slice is
        // copied from prior to the leaving of this function ensuring the raw
        // pointer is not persisted.
        let alias_bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                &report as *const sgx_quote_t as *const u8,
                mem::size_of::<sgx_quote_t>(),
            )
        };
        let mut bytes: [u8; mem::size_of::<sgx_quote_t>()] = [0; mem::size_of::<sgx_quote_t>()];
        bytes.copy_from_slice(alias_bytes);
        bytes
    }

    fn base_quote_1() -> sgx_quote_t {
        let report_body = sgx_report_body_t {
            misc_select: 18,
            ..Default::default()
        };

        sgx_quote_t {
            version: 11,
            sign_type: 0,
            epid_group_id: [13u8; 4],
            qe_svn: 14,
            pce_svn: 15,
            xeid: 16,
            basename: sgx_basename_t { name: [17u8; 32] },
            report_body,
            signature_len: 19,
            signature: Default::default(),
        }
    }

    fn base_quote_2() -> sgx_quote_t {
        let report_body = sgx_report_body_t {
            misc_select: 28,
            ..Default::default()
        };

        sgx_quote_t {
            version: 21,
            sign_type: 1,
            epid_group_id: [23u8; 4],
            qe_svn: 24,
            pce_svn: 25,
            xeid: 26,
            basename: sgx_basename_t { name: [27u8; 32] },
            report_body,
            signature_len: 29,
            signature: Default::default(),
        }
    }

    #[test]
    fn raw_quote_from_slice() {
        let bytes = [3u8; 14].as_slice();
        let raw: RawQuote = bytes.into();
        assert_eq!(raw.bytes, bytes);
    }

    #[test]
    fn quote_from_raw_quote() {
        let bytes = [8u8; 20].as_slice();
        let raw: RawQuote = bytes.into();
        let quote: Quote = raw.clone().into();
        assert_eq!(quote.0, raw);
    }

    #[test]
    fn quote_from_slice() {
        let bytes = [4u8; 6].as_slice();
        let quote: Quote = bytes.into();
        assert_eq!(quote.0.bytes, bytes);
    }

    #[test]
    fn quote_from_bytes_1x() {
        let quote_bytes = quote_to_bytes(base_quote_1());
        let quote = Quote::from(quote_bytes.as_slice());
        assert_eq!(quote._version(), 11.into());
        assert_eq!(
            quote._signature_type().unwrap(),
            QuoteSignatureKind::UnLinkable
        );
        assert_eq!(quote._epid_group_id(), EpidGroupId::from([13u8; 4]));
        assert_eq!(quote._quoting_enclave_svn(), IsvSvn::from(14));
        assert_eq!(
            quote._provisioning_certification_enclave_svn(),
            IsvSvn::from(15)
        );
        assert_eq!(
            quote._extended_epid_group_id(),
            EpidGroupId::from([16u8, 0u8, 0u8, 0u8])
        );
        assert_eq!(quote._basename(), Basename::from([17u8; BASENAME_SIZE]));

        let report_body = sgx_report_body_t {
            misc_select: 18,
            ..Default::default()
        };
        assert_eq!(quote._report_body().unwrap(), report_body.into());
    }

    #[test]
    fn quote_from_bytes_2x() {
        let quote_bytes = quote_to_bytes(base_quote_2());
        let quote = Quote::from(quote_bytes.as_slice());
        assert_eq!(quote._version(), 21.into());
        assert_eq!(
            quote._signature_type().unwrap(),
            QuoteSignatureKind::Linkable
        );
        assert_eq!(quote._epid_group_id(), EpidGroupId::from([23u8; 4]));
        assert_eq!(quote._quoting_enclave_svn(), IsvSvn::from(24));
        assert_eq!(
            quote._provisioning_certification_enclave_svn(),
            IsvSvn::from(25)
        );
        assert_eq!(quote._basename(), Basename::from([27u8; BASENAME_SIZE]));

        let report_body = sgx_report_body_t {
            misc_select: 28,
            ..Default::default()
        };
        assert_eq!(quote._report_body().unwrap(), report_body.into());
    }

    #[test]
    fn default_update_info() {
        let info = UpdateInfoBit::default();
        assert!(!info.ucode_needs_update());
        assert!(!info.csme_firmware_needs_update());
        assert!(!info.platform_software_needs_update());
    }

    #[test]
    fn all_update_info_needs_update() {
        let sgx_info = sgx_update_info_bit_t {
            ucodeUpdate: 1,
            csmeFwUpdate: 1,
            pswUpdate: 1,
        };

        let info = UpdateInfoBit::from(sgx_info);
        assert!(info.ucode_needs_update());
        assert!(info.csme_firmware_needs_update());
        assert!(info.platform_software_needs_update());
    }

    #[test]
    fn default_quoting_enclave_report_info() {
        let info = QuotingEnclaveReportInfo::default();
        assert_eq!(info.nonce(), QuoteNonce::default());
        assert_eq!(info.app_enclave_target_info(), TargetInfo::default());
        assert_eq!(info.report(), Report::default());
    }

    #[test]
    fn quoting_enclave_report_info_from_sgx() {
        let mut sgx_info = sgx_qe_report_info_t::default();
        sgx_info.nonce.rand = [1u8; 16];
        sgx_info.app_enclave_target_info.config_svn = 2;
        sgx_info.qe_report.body.misc_select = 3;
        let info = QuotingEnclaveReportInfo::from(sgx_info);

        assert_eq!(info.nonce(), QuoteNonce::from([1u8; 16]));

        let target_info = sgx_target_info_t {
            config_svn: 2,
            ..Default::default()
        };
        assert_eq!(
            info.app_enclave_target_info(),
            TargetInfo::from(target_info)
        );

        let mut report = sgx_report_t::default();
        report.body.misc_select = 3;
        assert_eq!(info.report(), Report::from(report));
    }

    #[test]
    fn serializing_quote_nonce() {
        let nonce = QuoteNonce::from([1u8; 16]);
        let serialized = serde_cbor::to_vec(&nonce).expect("Failed to serialize nonce");
        let new_nonce = serde_cbor::from_slice(&serialized).expect("Failed to deserialize nonce");
        assert_eq!(nonce, new_nonce);
    }
}
