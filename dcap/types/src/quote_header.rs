// Copyright (c) 2022 The MobileCoin Foundation

//! This module provides types related to Quote v3

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

#[cfg(test)]
mod test {
    use super::*;

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
        let sgx_header = sgx_quote_header_t {
            version: 1,
            att_key_type: Algorithm::EcdsaP256 as u16,
            att_key_data_0: 2,
            qe_svn: IsvSvn::from(4).into(),
            pce_svn: IsvSvn::from(5).into(),
            vendor_id: [6u8; 16],
            user_data: [7u8; 20],
        };

        let header: QuoteHeader = sgx_header.into();
        assert_eq!(header.version(), 1);
        assert_eq!(header.attestation_key_type().unwrap(), Algorithm::EcdsaP256);
        assert_eq!(header.attestation_key_raw(), 2);
        assert_eq!(header.qe_svn(), IsvSvn::from(4));
        assert_eq!(header.pce_svn(), IsvSvn::from(5));
        assert_eq!(header.vendor_id(), [6u8; 16]);
        assert_eq!(header.user_data(), [7u8; 20]);
    }
}
