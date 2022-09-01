// Copyright (c) 2022 The MobileCoin Foundation
//! Quote types

use crate::{
    attestation_key::QuoteSignatureKind, impl_newtype_for_bytestruct, new_type_accessors_impls,
    FfiError, IsvSvn, ReportBody,
};
use core::mem;
use mc_sgx_core_sys_types::{
    sgx_basename_t, sgx_epid_group_id_t, sgx_quote_nonce_t, sgx_quote_sign_type_t,
    sgx_report_body_t,
};

/// EPID Group ID
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct EpidGroupId(sgx_epid_group_id_t);

new_type_accessors_impls! {
    EpidGroupId, sgx_epid_group_id_t;
}

const BASENAME_SIZE: usize = 32;

/// Basename
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct Basename(sgx_basename_t);

impl_newtype_for_bytestruct! {
    Basename, sgx_basename_t, BASENAME_SIZE, name;
}

const NONCE_SIZE: usize = 16;

/// Quote Nonce
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct QuoteNonce(sgx_quote_nonce_t);

impl_newtype_for_bytestruct! {
    QuoteNonce, sgx_quote_nonce_t, NONCE_SIZE, rand;
}

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

new_type_accessors_impls! {
    Version, u16;
}

pub trait BaseQuote {
    /// Provides access to the [`RawQuote`] to perform the common lookup
    /// operations on the basic quote type.
    fn raw_quote(&self) -> &RawQuote;

    /// Version of the quote
    fn version(&self) -> Version {
        let bytes = self.raw_quote().bytes[..2]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `version`");
        u16::from_le_bytes(bytes).into()
    }

    /// The signature type
    fn signature_type(&self) -> Result<QuoteSignatureKind, FfiError> {
        let bytes = self.raw_quote().bytes[2..4]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `sign_type`");
        sgx_quote_sign_type_t(u16::from_le_bytes(bytes) as u32).try_into()
    }

    /// EPID group id
    fn epid_group_id(&self) -> EpidGroupId {
        let bytes: [u8; 4] = self.raw_quote().bytes[4..8]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `epid_group_id`");
        bytes.into()
    }

    /// Quoting enclave (QE) SVN (Security Version Number)
    fn quoting_enclave_svn(&self) -> IsvSvn {
        let bytes = self.raw_quote().bytes[8..10]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `qe_svn`");
        u16::from_le_bytes(bytes).into()
    }

    /// Provisioning certification enclave (PCE) SVN (Security Version Number)
    fn provisioning_certification_enclave_svn(&self) -> IsvSvn {
        let bytes = self.raw_quote().bytes[10..12]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `pce_svn`");
        u16::from_le_bytes(bytes).into()
    }

    /// Extended EPID group id
    fn extended_epid_group_id(&self) -> EpidGroupId {
        let bytes: [u8; 4] = self.raw_quote().bytes[12..16]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `xeid`");
        bytes.into()
    }

    /// Basename
    fn basename(&self) -> Basename {
        let bytes: [u8; BASENAME_SIZE] = self.raw_quote().bytes[16..48]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `basename`");
        bytes.into()
    }

    /// Report body
    fn report_body(&self) -> ReportBody {
        let bytes: [u8; mem::size_of::<sgx_report_body_t>()] = self.raw_quote().bytes[48..432]
            .try_into()
            .expect("Quote bytes aren't big enough to hold `report_body`");
        bytes.into()
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
    fn raw_quote(&self) -> &RawQuote {
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
    use mc_sgx_core_sys_types::{sgx_quote_t, sgx_report_body_t};

    fn base_quote_1() -> [u8; mem::size_of::<sgx_quote_t>()] {
        let mut report_body = sgx_report_body_t::default();
        report_body.misc_select = 18;

        let quote = sgx_quote_t {
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
        };
        let alias_bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                &quote as *const sgx_quote_t as *const u8,
                mem::size_of::<sgx_quote_t>(),
            )
        };
        let mut bytes: [u8; mem::size_of::<sgx_quote_t>()] = [0; mem::size_of::<sgx_quote_t>()];
        bytes.copy_from_slice(alias_bytes);
        bytes
    }

    fn base_quote_2() -> [u8; mem::size_of::<sgx_quote_t>()] {
        let mut report_body = sgx_report_body_t::default();
        report_body.misc_select = 28;

        let quote = sgx_quote_t {
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
        };
        let alias_bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                &quote as *const sgx_quote_t as *const u8,
                mem::size_of::<sgx_quote_t>(),
            )
        };
        let mut bytes: [u8; mem::size_of::<sgx_quote_t>()] = [0; mem::size_of::<sgx_quote_t>()];
        bytes.copy_from_slice(alias_bytes);
        bytes
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
        let quote_bytes = base_quote_1();
        let quote = Quote::from(quote_bytes.as_slice());
        assert_eq!(quote.version(), 11.into());
        assert_eq!(
            quote.signature_type().unwrap(),
            QuoteSignatureKind::UnLinkable
        );
        assert_eq!(quote.epid_group_id(), EpidGroupId::from([13u8; 4]));
        assert_eq!(quote.quoting_enclave_svn(), IsvSvn::from(14));
        assert_eq!(
            quote.provisioning_certification_enclave_svn(),
            IsvSvn::from(15)
        );
        assert_eq!(
            quote.extended_epid_group_id(),
            EpidGroupId::from([16u8, 0u8, 0u8, 0u8])
        );
        assert_eq!(quote.basename(), Basename::from([17u8; BASENAME_SIZE]));

        let mut report_body = sgx_report_body_t::default();
        report_body.misc_select = 18;
        assert_eq!(quote.report_body(), report_body.into());
    }

    #[test]
    fn quote_from_bytes_2x() {
        let quote_bytes = base_quote_2();
        let quote = Quote::from(quote_bytes.as_slice());
        assert_eq!(quote.version(), 21.into());
        assert_eq!(
            quote.signature_type().unwrap(),
            QuoteSignatureKind::Linkable
        );
        assert_eq!(quote.epid_group_id(), EpidGroupId::from([23u8; 4]));
        assert_eq!(quote.quoting_enclave_svn(), IsvSvn::from(24));
        assert_eq!(
            quote.provisioning_certification_enclave_svn(),
            IsvSvn::from(25)
        );
        assert_eq!(quote.basename(), Basename::from([27u8; BASENAME_SIZE]));

        let mut report_body = sgx_report_body_t::default();
        report_body.misc_select = 28;
        assert_eq!(quote.report_body(), report_body.into());
    }
}
