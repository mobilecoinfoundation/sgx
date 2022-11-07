// Copyright (c) 2022 The MobileCoin Foundation
//! Attestation Key types

use crate::{
    new_type_accessors_impls,
    report::{ExtendedProductId, FamilyId},
    ConfigId, FfiError,
};
use mc_sgx_core_sys_types::{sgx_att_key_id_ext_t, sgx_ql_att_key_id_t, sgx_quote_sign_type_t};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum MrSignerKeyHash {
    Sha256([u8; 32]),
    Sha384([u8; 48]),
}

/// The algorithm used in attestation
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum Algorithm {
    #[default]
    /// Epid 2.0, Anonymous
    Epid,

    /// Reserved
    Reserved,

    /// ECDSA-256 with P-256 curve, Non Anonymous
    EcdsaP256,

    /// ECDSA-384 with P-384 curve, Non Anonymous (Not currently supported)
    EcdsaP384,
}

impl TryFrom<u32> for Algorithm {
    type Error = FfiError;
    fn try_from(algorithm: u32) -> Result<Algorithm, FfiError> {
        match algorithm {
            0 => Ok(Algorithm::Epid),
            1 => Ok(Algorithm::Reserved),
            2 => Ok(Algorithm::EcdsaP256),
            3 => Ok(Algorithm::EcdsaP384),
            v => Err(FfiError::UnknownEnumValue(v.into())),
        }
    }
}

#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct Version(u16);

new_type_accessors_impls! {
    Version, u16;
}

#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct Id(u16);

new_type_accessors_impls! {
    Id, u16;
}

/// The type of quote.  Only valid for EPID quotes.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum QuoteSignatureKind {
    UnLinkable,
    Linkable,
}

impl TryFrom<sgx_quote_sign_type_t> for QuoteSignatureKind {
    type Error = FfiError;
    fn try_from(sign_type: sgx_quote_sign_type_t) -> Result<QuoteSignatureKind, FfiError> {
        match sign_type {
            // Per the header `sgx_quote.h` and
            // https://download.01.org/intel-sgx/sgx-linux/2.17.1/docs/Intel_SGX_Developer_Reference_Linux_2.17.1_Open_Source.pdf
            // the `sgx_att_key_id_ext_t::att_key_type` is only valid for EPID
            // quotes it will be 0 otherwise, which also happens to map to
            // SGX_UNLINKABLE_SIGNATURE.
            sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE => Ok(QuoteSignatureKind::UnLinkable),
            sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE => Ok(QuoteSignatureKind::Linkable),
            v => Err(FfiError::UnknownEnumValue(v.0.into())),
        }
    }
}

/// Attestation key from th quoting library.  contains the quoting enclaves ID
/// and the attestation algorithm
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct AttestationKeyId(sgx_ql_att_key_id_t);

impl AttestationKeyId {
    /// The ID
    pub fn id(&self) -> Id {
        self.0.id.into()
    }

    /// The key version
    pub fn version(&self) -> Version {
        self.0.version.into()
    }

    /// The hash of the MRSIGNER key.
    ///
    /// # Errors
    /// When the length of the hash is not a valid length for a hash,
    /// [`sgx_ql_att_key_id_t::mrsigner_length`].
    pub fn mr_signer_key_hash(&self) -> Result<MrSignerKeyHash, FfiError> {
        match self.0.mrsigner_length {
            32 => {
                let mut array: [u8; 32] = [0u8; 32];
                array.copy_from_slice(&self.0.mrsigner[..32]);
                Ok(MrSignerKeyHash::Sha256(array))
            }
            48 => {
                let mut array: [u8; 48] = [0u8; 48];
                array.copy_from_slice(&self.0.mrsigner[..48]);
                Ok(MrSignerKeyHash::Sha384(array))
            }
            _ => Err(FfiError::InvalidInputLength),
        }
    }

    /// The product ID
    pub fn product_id(&self) -> ExtendedProductId {
        self.0.extended_prod_id.into()
    }

    /// The config ID
    pub fn config_id(&self) -> ConfigId {
        self.0.config_id.into()
    }

    /// The family ID
    pub fn family_id(&self) -> FamilyId {
        self.0.family_id.into()
    }

    /// The algorithm ID
    pub fn algorithm_id(&self) -> Result<Algorithm, FfiError> {
        self.0.algorithm_id.try_into()
    }
}

new_type_accessors_impls! {
    AttestationKeyId, sgx_ql_att_key_id_t;
}

/// Service Provider ID
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct ServiceProviderId([u8; 16]);

new_type_accessors_impls! {
    ServiceProviderId, [u8; 16];
}

/// Extended Attestation Key ID
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct ExtendedAttestationKeyId(sgx_att_key_id_ext_t);

impl ExtendedAttestationKeyId {
    /// The base attestation key
    pub fn base_key_id(&self) -> AttestationKeyId {
        self.0.base.into()
    }

    /// Service provider id
    pub fn service_provider_id(&self) -> ServiceProviderId {
        self.0.spid.into()
    }

    /// Key type
    pub fn key_type(&self) -> u16 {
        self.0.att_key_type
    }
}

new_type_accessors_impls! {
    ExtendedAttestationKeyId, sgx_att_key_id_ext_t;
}

#[cfg(test)]
mod test {
    use super::*;
    use yare::parameterized;

    #[test]
    fn default_extended_attestation_key_id() {
        let key = ExtendedAttestationKeyId::default();
        assert_eq!(key.base_key_id(), AttestationKeyId::default());
        assert_eq!(key.service_provider_id(), ServiceProviderId([0u8; 16]));
        assert_eq!(key.key_type(), 0);
    }

    #[test]
    fn extended_attestation_key_id_from_sgx() {
        let mut base_key = AttestationKeyId::default();
        base_key.0.id = 20;
        let sgx_key = sgx_att_key_id_ext_t {
            base: base_key.clone().into(),
            spid: [10u8; 16],
            att_key_type: 5,
            reserved: [3u8; 80],
        };
        let key: ExtendedAttestationKeyId = sgx_key.into();
        assert_eq!(key.base_key_id(), base_key);
        assert_eq!(key.service_provider_id(), ServiceProviderId([10u8; 16]));
        assert_eq!(key.key_type(), 5);
    }

    #[test]
    fn default_attestation_key_id() {
        let key = AttestationKeyId::default();
        assert_eq!(key.id(), Id::default());
        assert_eq!(key.version(), Version::default());
        assert_eq!(key.mr_signer_key_hash(), Err(FfiError::InvalidInputLength));
        assert_eq!(key.product_id(), ExtendedProductId::default());
        assert_eq!(key.config_id(), ConfigId::default());
        assert_eq!(key.family_id(), FamilyId::default());
        assert_eq!(key.algorithm_id().unwrap(), Algorithm::default());
    }

    #[test]
    fn attestation_key_id_from_sgx() {
        let sgx_key = sgx_ql_att_key_id_t {
            id: 1,
            version: 2,
            mrsigner_length: 48,
            mrsigner: [4u8; 48],
            prod_id: 5,
            extended_prod_id: [6u8; 16],
            config_id: [7u8; 64],
            family_id: [8u8; 16],
            algorithm_id: Algorithm::Reserved as u32,
        };
        let key: AttestationKeyId = sgx_key.into();
        assert_eq!(key.id(), Id(1));
        assert_eq!(key.version(), Version(2));
        assert_eq!(
            key.mr_signer_key_hash(),
            Ok(MrSignerKeyHash::Sha384([4u8; 48]))
        );
        assert_eq!(key.product_id(), ExtendedProductId::from([6u8; 16]));
        assert_eq!(key.config_id(), ConfigId::from([7u8; 64]));
        assert_eq!(key.family_id(), FamilyId::from([8u8; 16]));
        assert_eq!(key.algorithm_id().unwrap(), Algorithm::Reserved);
    }

    #[parameterized(
    nothing = {0},
    too_small_256 = {31},
    too_large_256 = {33},
    too_small_384 = {47},
    too_large_384 = {49},
    )]
    fn invalid_mr_signer_length(length: u16) {
        let mut key = AttestationKeyId::default();
        key.0.mrsigner_length = length;
        assert_eq!(key.mr_signer_key_hash(), Err(FfiError::InvalidInputLength));
    }

    #[parameterized(
    unlinkable = {0, Ok(QuoteSignatureKind::UnLinkable)},
    linkable = {1, Ok(QuoteSignatureKind::Linkable)},
    out_of_bounds = {2, Err(FfiError::UnknownEnumValue(2))},
    )]
    fn try_from_signature_type(raw_value: u32, result: Result<QuoteSignatureKind, FfiError>) {
        assert_eq!(
            QuoteSignatureKind::try_from(sgx_quote_sign_type_t(raw_value)),
            result
        );
    }

    #[parameterized(
    epid = {0, Ok(Algorithm::Epid)},
    ecdsa_p384 = {3, Ok(Algorithm::EcdsaP384)},
    out_of_bounds = {4, Err(FfiError::UnknownEnumValue(4))},
    )]
    fn try_from_algorithm(value: u32, result: Result<Algorithm, FfiError>) {
        assert_eq!(Algorithm::try_from(value), result);
    }
}
