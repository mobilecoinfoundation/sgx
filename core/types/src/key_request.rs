// Copyright (c) 2022 The MobileCoin Foundation
//! SGX key request rust types

use crate::{
    impl_newtype_for_bytestruct, new_type_accessors_impls, Attributes, ConfigSvn, CpuSvn, IsvSvn,
    MiscellaneousSelect,
};
use bitflags::bitflags;
use mc_sgx_core_sys_types::{
    sgx_key_128bit_t, sgx_key_id_t, sgx_key_request_t, SGX_KEYID_SIZE, SGX_KEYPOLICY_CONFIGID,
    SGX_KEYPOLICY_ISVEXTPRODID, SGX_KEYPOLICY_ISVFAMILYID, SGX_KEYPOLICY_MRENCLAVE,
    SGX_KEYPOLICY_MRSIGNER, SGX_KEYPOLICY_NOISVPRODID, SGX_KEYSELECT_EINITTOKEN,
    SGX_KEYSELECT_PROVISION, SGX_KEYSELECT_PROVISION_SEAL, SGX_KEYSELECT_REPORT,
    SGX_KEYSELECT_SEAL, SGX_KEY_REQUEST_RESERVED2_BYTES,
};
use rand_core::{CryptoRng, RngCore};

/// Key ID
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct KeyId(sgx_key_id_t);

impl_newtype_for_bytestruct! {
    KeyId, sgx_key_id_t, SGX_KEYID_SIZE, id;
}

/// Key Name
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u16)]
pub enum KeyName {
    /// Launch key
    EnclaveInitializationToken = SGX_KEYSELECT_EINITTOKEN,

    /// Provisioning Key
    Provision = SGX_KEYSELECT_PROVISION,

    /// Provisioning Seal Key
    ProvisionSeal = SGX_KEYSELECT_PROVISION_SEAL,

    /// Report Key
    Report = SGX_KEYSELECT_REPORT,

    /// Seal Key
    Seal = SGX_KEYSELECT_SEAL,
}

bitflags! {
    /// Policy to use for the key derivation
    pub struct KeyPolicy: u16 {
        /// Derive key using the enclave's ENCLAVE measurement register
        const MRENCLAVE = SGX_KEYPOLICY_MRENCLAVE;

        /// Derive key using the enclave's SINGER measurement register
        const MRSIGNER = SGX_KEYPOLICY_MRSIGNER;

        /// Derive key without the enclave's ISVPRODID
        const NO_ISV_PROD_ID = SGX_KEYPOLICY_NOISVPRODID;

        /// Derive key with the enclave's CONFIGID
        const CONFIG_ID = SGX_KEYPOLICY_CONFIGID;

        /// Derive key with the enclave's ISVFAMILYID
        const ISV_FAMILY_ID = SGX_KEYPOLICY_ISVFAMILYID;

        /// Derive key with the enclave's ISVEXTPRODID
        const ISV_EXTENDED_PROD_ID = SGX_KEYPOLICY_ISVEXTPRODID;
    }
}

/// Key request
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct KeyRequest(sgx_key_request_t);
new_type_accessors_impls! {
    KeyRequest, sgx_key_request_t;
}

/// A builder for creating a [`KeyRequest`]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct KeyRequestBuilder(sgx_key_request_t);

impl KeyRequestBuilder {
    /// Creates a new [KeyRequestBuilder].
    ///
    /// # Arguments
    ///
    /// * `csprng` - A cryptographic psuedo random number generator used to
    ///   ensure similar key requests don't collide.
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let mut wear_out_protection = [0u8; SGX_KEYID_SIZE];
        csprng.fill_bytes(&mut wear_out_protection);

        Self(sgx_key_request_t {
            key_name: 0,
            key_policy: 0,
            isv_svn: 0,
            reserved1: 0,
            cpu_svn: CpuSvn::default().into(),
            attribute_mask: Attributes::default().into(),
            key_id: sgx_key_id_t {
                id: wear_out_protection,
            },
            misc_mask: MiscellaneousSelect::default().into(),
            config_svn: 0,
            reserved2: [0; SGX_KEY_REQUEST_RESERVED2_BYTES],
        })
    }

    /// Build the [KeyRequest]
    pub fn build(self) -> KeyRequest {
        KeyRequest(self.0)
    }

    /// The key name to use in the key request
    ///
    /// # Arguments
    ///
    /// * `key_name` - The key name to use
    pub fn key_name(mut self, key_name: KeyName) -> Self {
        self.0.key_name = key_name as u16;
        self
    }

    /// The key policy to use in the key request
    ///
    /// # Arguments
    ///
    /// * `key_policy` - The key policy to use
    pub fn key_policy(mut self, key_policy: KeyPolicy) -> Self {
        self.0.key_policy = key_policy.bits();
        self
    }

    /// The ISV(Individual Software Vendor) SVN (Security Version Number) of
    /// the key request
    ///
    /// # Arguments
    ///
    /// * `isv_svn` - The ISV SVN to use
    pub fn isv_svn(mut self, isv_svn: &IsvSvn) -> Self {
        self.0.isv_svn = isv_svn.clone().into();
        self
    }

    /// The CPU SVN (Security Version Number) of the key request
    ///
    /// # Arguments
    ///
    /// * `cpu_svn` - The CPU SVN to use
    pub fn cpu_svn(mut self, cpu_svn: &CpuSvn) -> Self {
        self.0.cpu_svn = cpu_svn.clone().into();
        self
    }

    /// The attributes of the key request
    ///
    /// # Arguments
    ///
    /// * `attributes` - The attributes to use
    pub fn attributes(mut self, attributes: &Attributes) -> Self {
        self.0.attribute_mask = attributes.clone().into();
        self
    }

    /// The miscellaneous select values
    ///
    /// # Arguments
    ///
    /// * `miscellaneous_select` - The miscellaneous select values to use
    pub fn miscellaneous_select(mut self, miscellaneous_select: &MiscellaneousSelect) -> Self {
        self.0.misc_mask = miscellaneous_select.clone().into();
        self
    }

    /// The config SVN (Security Version Number) of the key request
    ///
    /// # Arguments
    ///
    /// * `config_svn` - The config SVN to use
    pub fn config_svn(mut self, config_svn: &ConfigSvn) -> Self {
        self.0.config_svn = config_svn.clone().into();
        self
    }
}

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Key128bit(sgx_key_128bit_t);

new_type_accessors_impls! {
    Key128bit, sgx_key_128bit_t;
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use mc_sgx_core_sys_types::SGX_CPUSVN_SIZE;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn new_key_request_all_zero_except_key_id() {
        let mut csprng = StdRng::from_seed([1; 32]);
        let request = KeyRequestBuilder::new(&mut csprng).build();

        assert_eq!(request.0.key_name, 0);
        assert_eq!(request.0.key_policy, 0);
        assert_eq!(request.0.isv_svn, 0);
        assert_eq!(request.0.cpu_svn.svn, [0; SGX_CPUSVN_SIZE]);
        assert_eq!(request.0.attribute_mask.flags, 0);
        assert_eq!(request.0.attribute_mask.xfrm, 0);
        assert_eq!(request.0.misc_mask, 0);
        assert_eq!(request.0.config_svn, 0);
        assert_ne!(request.0.key_id.id, [0; SGX_KEYID_SIZE]);
    }

    #[test]
    fn build_key_request() {
        let mut csprng = StdRng::from_seed([8; 32]);
        let request = KeyRequestBuilder::new(&mut csprng)
            .key_name(KeyName::Provision)
            .key_policy(KeyPolicy::MRENCLAVE | KeyPolicy::NO_ISV_PROD_ID)
            .isv_svn(&IsvSvn::from(2))
            .cpu_svn(&CpuSvn::from([3; CpuSvn::SIZE]))
            .attributes(
                &Attributes::default()
                    .set_flags(4)
                    .set_extended_features_mask(6),
            )
            .miscellaneous_select(&7.into())
            .config_svn(&ConfigSvn::from(8))
            .build();

        assert_eq!(request.0.key_name, 1);
        assert_eq!(request.0.key_policy, 5);
        assert_eq!(request.0.isv_svn, 2);
        assert_eq!(request.0.cpu_svn.svn, [3; SGX_CPUSVN_SIZE]);
        assert_eq!(request.0.attribute_mask.flags, 4);
        assert_eq!(request.0.attribute_mask.xfrm, 6);
        assert_eq!(request.0.misc_mask, 7);
        assert_eq!(request.0.config_svn, 8);
    }

    #[test]
    fn key_from_sgx_key() {
        let sgx_key = [1u8; 16];
        let key: Key128bit = sgx_key.into();
        assert_eq!(key.0, sgx_key);
    }

    #[test]
    fn sgx_key_from_key() {
        let key = Key128bit::default();
        let sgx_key: sgx_key_128bit_t = key.into();
        assert_eq!(sgx_key, [0u8; 16]);
    }
}
