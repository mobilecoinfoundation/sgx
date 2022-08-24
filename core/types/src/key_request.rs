// Copyright (c) 2022 The MobileCoin Foundation
//! SGX key request rust types

use crate::{new_type_wrapper, Attributes, MiscellaneousSelect};
use mc_sgx_core_sys_types::{
    sgx_config_svn_t, sgx_cpu_svn_t, sgx_isv_svn_t, sgx_key_id_t, sgx_key_request_t,
    SGX_CPUSVN_SIZE, SGX_KEYID_SIZE, SGX_KEYPOLICY_CONFIGID, SGX_KEYPOLICY_ISVEXTPRODID,
    SGX_KEYPOLICY_ISVFAMILYID, SGX_KEYPOLICY_MRENCLAVE, SGX_KEYPOLICY_MRSIGNER,
    SGX_KEYPOLICY_NOISVPRODID, SGX_KEYSELECT_EINITTOKEN, SGX_KEYSELECT_PROVISION,
    SGX_KEYSELECT_PROVISION_SEAL, SGX_KEYSELECT_REPORT, SGX_KEYSELECT_SEAL,
    SGX_KEY_REQUEST_RESERVED2_BYTES,
};
use rand::{CryptoRng, RngCore};

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

#[repr(transparent)]
#[derive(Clone, Hash, PartialEq, Eq, Debug, Copy)]
pub struct KeyPolicy(u16);
impl KeyPolicy {
    /// Derive key using the enclave's ENCLAVE measurement register
    pub const MRENCLAVE: KeyPolicy = KeyPolicy(SGX_KEYPOLICY_MRENCLAVE);

    /// Derive key using the enclave's SINGER measurement register
    pub const MRSIGNER: KeyPolicy = KeyPolicy(SGX_KEYPOLICY_MRSIGNER);

    /// Derive key without the enclave's ISVPRODID
    pub const NO_ISV_PROD_ID: KeyPolicy = KeyPolicy(SGX_KEYPOLICY_NOISVPRODID);

    /// Derive key with the enclave's CONFIGID
    pub const CONFIG_ID: KeyPolicy = KeyPolicy(SGX_KEYPOLICY_CONFIGID);

    /// Derive key with the enclave's ISVFAMILYID
    pub const ISV_FAMILY_ID: KeyPolicy = KeyPolicy(SGX_KEYPOLICY_ISVFAMILYID);

    /// Derive key with the enclave's ISVEXTPRODID
    pub const ISV_EXTENDED_PROD_ID: KeyPolicy = KeyPolicy(SGX_KEYPOLICY_ISVEXTPRODID);
}

impl core::ops::BitOr<KeyPolicy> for KeyPolicy {
    type Output = Self;
    #[inline]
    fn bitor(self, other: Self) -> Self {
        KeyPolicy(self.0 | other.0)
    }
}
impl ::core::ops::BitOrAssign for KeyPolicy {
    #[inline]
    fn bitor_assign(&mut self, rhs: KeyPolicy) {
        self.0 |= rhs.0;
    }
}
impl ::core::ops::BitAnd<KeyPolicy> for KeyPolicy {
    type Output = Self;
    #[inline]
    fn bitand(self, other: Self) -> Self {
        KeyPolicy(self.0 & other.0)
    }
}
impl ::core::ops::BitAndAssign for KeyPolicy {
    #[inline]
    fn bitand_assign(&mut self, rhs: KeyPolicy) {
        self.0 &= rhs.0;
    }
}

new_type_wrapper! {
    ConfigSvn, sgx_config_svn_t;
}

// Suppress clippy as the `new_type_wrapper` macro can't derive Default for many
// of the types.
#[allow(clippy::derivable_impls)]
impl Default for ConfigSvn {
    fn default() -> Self {
        ConfigSvn(0)
    }
}

new_type_wrapper! {
    IsvSvn, sgx_isv_svn_t;
}

#[allow(clippy::derivable_impls)]
impl Default for IsvSvn {
    fn default() -> Self {
        IsvSvn(0)
    }
}

new_type_wrapper! {
    CpuSvn, sgx_cpu_svn_t;
}

impl Default for CpuSvn {
    fn default() -> Self {
        CpuSvn(sgx_cpu_svn_t {
            svn: [0; SGX_CPUSVN_SIZE],
        })
    }
}

new_type_wrapper! {
    KeyRequest, sgx_key_request_t;
}

impl KeyRequest {
    /// Creates a new [KeyRequest].
    ///
    /// The [KeyRequest] will be mostly empty and can be built up using the
    /// setter methods like [KeyRequest::set_isv_svn]
    ///
    /// # Arguments
    ///
    /// * `csprng` - A cryptographic psuedo random number generator used to
    ///   ensure similar key requests don't collide.
    pub fn new<R: CryptoRng + RngCore>(csprng: &mut R) -> Self {
        let mut wear_out_protection = [0u8; SGX_KEYID_SIZE];
        csprng.fill_bytes(&mut wear_out_protection);

        KeyRequest(sgx_key_request_t {
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
}

impl KeyRequest {
    /// Set the key name to use in the key request
    ///
    /// # Arguments
    ///
    /// * `key_name` - The key name to use
    pub fn set_key_name(mut self, key_name: KeyName) -> Self {
        self.0.key_name = ::core::intrinsics::discriminant_value(&key_name);
        self
    }

    /// Set the key policy to use in the key request
    ///
    /// # Arguments
    ///
    /// * `key_policy` - The key policy to use
    pub fn set_key_policy(mut self, key_policy: KeyPolicy) -> Self {
        self.0.key_policy = key_policy.0;
        self
    }

    /// Set the ISV(Individual Software Vendor) SVN (Security Version Number) of
    /// the key request
    ///
    /// # Arguments
    ///
    /// * `isv_svn` - The ISV SVN to use
    pub fn set_isv_svn(mut self, isv_svn: &IsvSvn) -> Self {
        self.0.isv_svn = isv_svn.clone().into();
        self
    }

    /// Set the CPU SVN (Security Version Number) of the key request
    ///
    /// # Arguments
    ///
    /// * `cpu_svn` - The CPU SVN to use
    pub fn set_cpu_svn(mut self, cpu_svn: &CpuSvn) -> Self {
        self.0.cpu_svn = cpu_svn.clone().into();
        self
    }

    /// Set the attributes of the key request
    ///
    /// # Arguments
    ///
    /// * `attributes` - The attributes to use
    pub fn set_attributes(mut self, attributes: &Attributes) -> Self {
        self.0.attribute_mask = attributes.clone().into();
        self
    }

    /// Set the miscellaneous select values
    ///
    /// # Arguments
    ///
    /// * `miscellaneous_select` - The miscellaneous select values to use
    pub fn set_miscellaneous_select(mut self, miscellaneous_select: &MiscellaneousSelect) -> Self {
        self.0.misc_mask = miscellaneous_select.clone().into();
        self
    }

    /// Set the config SVN (Security Version Number) of the key request
    ///
    /// # Arguments
    ///
    /// * `config_svn` - The config SVN to use
    pub fn set_config_svn(mut self, config_svn: &ConfigSvn) -> Self {
        self.0.config_svn = config_svn.clone().into();
        self
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn new_key_request_all_zero_except_key_id() {
        let mut csprng = StdRng::from_seed([1; 32]);
        let request = KeyRequest::new(&mut csprng);

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
        let request = KeyRequest::new(&mut csprng)
            .set_key_name(KeyName::Provision)
            .set_key_policy(KeyPolicy::MRENCLAVE | KeyPolicy::NO_ISV_PROD_ID)
            .set_isv_svn(&IsvSvn(2))
            .set_cpu_svn(&CpuSvn(sgx_cpu_svn_t {
                svn: [3; SGX_CPUSVN_SIZE],
            }))
            .set_attributes(&Attributes::default().set_flags(4).set_transform(6))
            .set_miscellaneous_select(&7.into())
            .set_config_svn(&ConfigSvn(8));

        assert_eq!(request.0.key_name, 1);
        assert_eq!(request.0.key_policy, 5);
        assert_eq!(request.0.isv_svn, 2);
        assert_eq!(request.0.cpu_svn.svn, [3; SGX_CPUSVN_SIZE]);
        assert_eq!(request.0.attribute_mask.flags, 4);
        assert_eq!(request.0.attribute_mask.xfrm, 6);
        assert_eq!(request.0.misc_mask, 7);
        assert_eq!(request.0.config_svn, 8);
    }
}
