// Copyright (c) 2022 The MobileCoin Foundation

//! This module provides types related to Quote v3

use core::mem;
use mc_sgx_core_types::{new_type_accessors_impls, Algorithm, FfiError, IsvSvn};
use mc_sgx_dcap_sys_types::sgx_quote_header_t;

/// The quote header
#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct QuoteHeader(sgx_quote_header_t);

impl QuoteHeader {
    /// The quote version
    pub fn version(&self) -> u16 {
        self.0.version
    }

    /// The attestation key type (algorithm)
    pub fn attestation_key_type(&self) -> Result<Algorithm, FfiError> {
        // It seems that SGX is inconsistent on the size of the key type.
        // Some places use 32 bit and others use 16 bit
        let key_type_32 = self.0.att_key_type as u32;
        key_type_32.try_into()
    }

    /// The raw attestation key
    pub fn attestation_key_raw(&self) -> u32 {
        self.0.att_key_data_0
    }

    /// The Quoting Enclave (QE) Security Version Number (SVN)
    pub fn qe_svn(&self) -> IsvSvn {
        self.0.qe_svn.into()
    }

    /// The Provisioning Certificate Enclave (PCE) Security Version Number (SVN)
    pub fn pce_svn(&self) -> IsvSvn {
        self.0.pce_svn.into()
    }

    /// The vendor ID of the Quoting Enclave
    pub fn vendor_id(&self) -> [u8; 16] {
        self.0.vendor_id
    }

    /// Custom attestation key owner data
    pub fn user_data(&self) -> [u8; 20] {
        self.0.user_data
    }
}

new_type_accessors_impls! {
    QuoteHeader, sgx_quote_header_t;
}

impl From<[u8; mem::size_of::<sgx_quote_header_t>()]> for QuoteHeader {
    fn from(bytes: [u8; mem::size_of::<sgx_quote_header_t>()]) -> Self {
        // A note about the `expect()` calls.  This size is specified in the
        // signature and there are unit tests ensuring the extraction from a
        // byte array.  The values should not fail to extract due to size
        // issues.
        let mut header = Self::default();
        header.0.version =
            u16::from_le_bytes(bytes[..2].try_into().expect("Failed to extract `version`"));
        header.0.att_key_type = u16::from_le_bytes(
            bytes[2..4]
                .try_into()
                .expect("Failed to extract `att_key_type`"),
        );
        header.0.att_key_data_0 = u32::from_le_bytes(
            bytes[4..8]
                .try_into()
                .expect("Failed to extract `att_key_data_0`"),
        );
        header.0.qe_svn =
            u16::from_le_bytes(bytes[8..10].try_into().expect("Failed to extract `qe_svn`"));
        header.0.pce_svn = u16::from_le_bytes(
            bytes[10..12]
                .try_into()
                .expect("Failed to extract `pce_svn`"),
        );
        header.0.vendor_id = bytes[12..28]
            .try_into()
            .expect("Failed to extract `vendor_id`");
        header.0.user_data = bytes[28..]
            .try_into()
            .expect("Failed to extract `user_data`");
        header
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::slice;

    fn header_1() -> sgx_quote_header_t {
        sgx_quote_header_t {
            version: 1,
            att_key_type: Algorithm::EcdsaP256 as u16,
            att_key_data_0: 2,
            qe_svn: IsvSvn::from(4).into(),
            pce_svn: IsvSvn::from(5).into(),
            vendor_id: [6u8; 16],
            user_data: [7u8; 20],
        }
    }

    fn header_2() -> sgx_quote_header_t {
        sgx_quote_header_t {
            version: 3,
            att_key_type: Algorithm::EcdsaP384 as u16,
            att_key_data_0: 5,
            qe_svn: IsvSvn::from(6).into(),
            pce_svn: IsvSvn::from(7).into(),
            vendor_id: [8u8; 16],
            user_data: [9u8; 20],
        }
    }

    #[allow(unsafe_code)]
    fn header_to_bytes(header: sgx_quote_header_t) -> [u8; mem::size_of::<sgx_quote_header_t>()] {
        // SAFETY: This is a test only function. The size of `header` is used
        // for reinterpretation of `header` into a byte slice. The slice is
        // copied from prior to the leaving of this function ensuring the raw
        // pointer is not persisted.
        let alias_bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                &header as *const sgx_quote_header_t as *const u8,
                mem::size_of::<sgx_quote_header_t>(),
            )
        };
        let mut bytes: [u8; mem::size_of::<sgx_quote_header_t>()] =
            [0; mem::size_of::<sgx_quote_header_t>()];
        bytes.copy_from_slice(alias_bytes);
        bytes
    }

    #[test]
    fn default_quote_header() {
        let header = QuoteHeader::default();
        assert_eq!(header.version(), 0);
        assert_eq!(header.attestation_key_type().unwrap(), Algorithm::Epid);
        assert_eq!(header.attestation_key_raw(), 0);
        assert_eq!(header.qe_svn(), IsvSvn::default());
        assert_eq!(header.pce_svn(), IsvSvn::default());
        assert_eq!(header.vendor_id(), [0u8; 16]);
        assert_eq!(header.user_data(), [0u8; 20]);
    }

    #[test]
    fn quote_header_from_sgx() {
        let header: QuoteHeader = header_1().into();
        assert_eq!(header.version(), 1);
        assert_eq!(header.attestation_key_type().unwrap(), Algorithm::EcdsaP256);
        assert_eq!(header.attestation_key_raw(), 2);
        assert_eq!(header.qe_svn(), IsvSvn::from(4));
        assert_eq!(header.pce_svn(), IsvSvn::from(5));
        assert_eq!(header.vendor_id(), [6u8; 16]);
        assert_eq!(header.user_data(), [7u8; 20]);
    }

    #[test]
    fn header_1_from_bytes() {
        let bytes = header_to_bytes(header_1());
        let header = QuoteHeader::from(bytes);
        assert_eq!(header.version(), 1);
        assert_eq!(header.attestation_key_type().unwrap(), Algorithm::EcdsaP256);
        assert_eq!(header.attestation_key_raw(), 2);
        assert_eq!(header.qe_svn(), IsvSvn::from(4));
        assert_eq!(header.pce_svn(), IsvSvn::from(5));
        assert_eq!(header.vendor_id(), [6u8; 16]);
        assert_eq!(header.user_data(), [7u8; 20]);
    }

    #[test]
    fn header_2_from_bytes() {
        let bytes = header_to_bytes(header_2());
        let header = QuoteHeader::from(bytes);
        assert_eq!(header.version(), 3);
        assert_eq!(header.attestation_key_type().unwrap(), Algorithm::EcdsaP384);
        assert_eq!(header.attestation_key_raw(), 5);
        assert_eq!(header.qe_svn(), IsvSvn::from(6));
        assert_eq!(header.pce_svn(), IsvSvn::from(7));
        assert_eq!(header.vendor_id(), [8u8; 16]);
        assert_eq!(header.user_data(), [9u8; 20]);
    }
}
