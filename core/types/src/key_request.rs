// Copyright (c) 2022 The MobileCoin Foundation
//! SGX key request rust types

use crate::{
    impl_newtype_for_bytestruct, new_type_accessors_impls, Attributes, ConfigSvn, CpuSvn, IsvSvn,
    MiscellaneousSelect,
};
use bitflags::bitflags;
use mc_sgx_core_sys_types::{
    sgx_key_128bit_t, sgx_key_id_t, sgx_key_request_t, SGX_CPUSVN_SIZE, SGX_KEYID_SIZE,
    SGX_KEYPOLICY_CONFIGID, SGX_KEYPOLICY_ISVEXTPRODID, SGX_KEYPOLICY_ISVFAMILYID,
    SGX_KEYPOLICY_MRENCLAVE, SGX_KEYPOLICY_MRSIGNER, SGX_KEYPOLICY_NOISVPRODID,
    SGX_KEYSELECT_EINITTOKEN, SGX_KEYSELECT_PROVISION, SGX_KEYSELECT_PROVISION_SEAL,
    SGX_KEYSELECT_REPORT, SGX_KEYSELECT_SEAL, SGX_KEY_REQUEST_RESERVED2_BYTES,
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

impl From<&[u8; 512]> for KeyRequest {
    // Using `512` here instead of `sgx_key_request_t` to avoid leaking the
    // abstraction to users
    fn from(bytes: &[u8; 512]) -> Self {
        // Unfortunately the `sgx_key_request_t` is not packed, as such we're
        // relying on compiler convention as an assurance that the expected size
        // is 512 bytes.
        static_assertions::assert_eq_size!([u8; 512], sgx_key_request_t);

        // A note about the `expect()` calls.  This size is specified in the
        // signature and there are unit tests ensuring the extraction from a
        // byte array.  The values should not fail to extract due to size
        // issues.
        let mut request = KeyRequest(sgx_key_request_t::default());
        request.0.key_name =
            u16::from_le_bytes(bytes[..2].try_into().expect("Failed to extract `key_name`"));
        request.0.key_policy = u16::from_le_bytes(
            bytes[2..4]
                .try_into()
                .expect("Failed to extract `key_policy`"),
        );
        request.0.isv_svn =
            u16::from_le_bytes(bytes[4..6].try_into().expect("Failed to extract `isv_svn`"));
        // Copying reserved bytes out to ensure forward compatibility if these
        // bytes start to get utilized for internal communication between SGX
        // c functions.
        request.0.reserved1 = u16::from_le_bytes(
            bytes[6..8]
                .try_into()
                .expect("Failed to extract `reserved1`"),
        );
        let cpu_svn: [u8; SGX_CPUSVN_SIZE] = bytes[8..24]
            .try_into()
            .expect("Failed to extract `cpu_svn`");
        request.0.cpu_svn = CpuSvn::from(cpu_svn).into();
        request.0.attribute_mask.flags = u64::from_le_bytes(
            bytes[24..32]
                .try_into()
                .expect("Failed to extract `attribute_mask.flags`"),
        );
        request.0.attribute_mask.xfrm = u64::from_le_bytes(
            bytes[32..40]
                .try_into()
                .expect("Failed to extract `attribute_mask.xfrm`"),
        );
        let key_id: [u8; SGX_KEYID_SIZE] = bytes[40..72]
            .try_into()
            .expect("Failed to extract `key_id`");
        request.0.key_id = KeyId::from(key_id).into();
        request.0.misc_mask = u32::from_le_bytes(
            bytes[72..76]
                .try_into()
                .expect("Failed to extract `misc_mask`"),
        );
        request.0.config_svn = u16::from_le_bytes(
            bytes[76..78]
                .try_into()
                .expect("Failed to extract `config_svn`"),
        );
        // Copying reserved bytes out to ensure forward compatibility if these
        // bytes start to get utilized for internal communication between SGX
        // c functions.
        request.0.reserved2.copy_from_slice(
            bytes[78..512]
                .try_into()
                .expect("Failed to extract `reserved2`"),
        );
        request
    }
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
    use core::{mem, slice};
    use mc_sgx_core_sys_types::{sgx_attributes_t, sgx_cpu_svn_t, SGX_CPUSVN_SIZE};
    use rand::{rngs::StdRng, SeedableRng};

    #[allow(unsafe_code)]
    fn key_request_to_bytes(
        request: sgx_key_request_t,
    ) -> [u8; mem::size_of::<sgx_key_request_t>()] {
        // SAFETY: This is a test only function. The size of `request` is used
        // for reinterpretation of `request` into a byte slice. The slice is
        // copied from prior to the leaving of this function ensuring the raw
        // pointer is not persisted.
        let alias_bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                &request as *const sgx_key_request_t as *const u8,
                mem::size_of::<sgx_key_request_t>(),
            )
        };
        let mut bytes: [u8; mem::size_of::<sgx_key_request_t>()] =
            [0; mem::size_of::<sgx_key_request_t>()];
        bytes.copy_from_slice(alias_bytes);
        bytes
    }

    fn request_1() -> sgx_key_request_t {
        sgx_key_request_t {
            key_name: 1,
            key_policy: 2,
            isv_svn: 3,
            reserved1: 4,
            cpu_svn: sgx_cpu_svn_t {
                svn: [5; SGX_CPUSVN_SIZE],
            },
            attribute_mask: sgx_attributes_t { flags: 6, xfrm: 7 },
            key_id: sgx_key_id_t {
                id: [8u8; SGX_KEYID_SIZE],
            },
            misc_mask: 9,
            config_svn: 10,
            reserved2: [11u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
        }
    }

    fn request_2() -> sgx_key_request_t {
        sgx_key_request_t {
            key_name: 21,
            key_policy: 22,
            isv_svn: 23,
            reserved1: 24,
            cpu_svn: sgx_cpu_svn_t {
                svn: [25; SGX_CPUSVN_SIZE],
            },
            attribute_mask: sgx_attributes_t {
                flags: 26,
                xfrm: 27,
            },
            key_id: sgx_key_id_t {
                id: [28u8; SGX_KEYID_SIZE],
            },
            misc_mask: 29,
            config_svn: 210,
            reserved2: [211u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
        }
    }

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

    #[test]
    fn key_request_from_bytes_1() {
        let bytes = key_request_to_bytes(request_1());
        let request = KeyRequest::from(&bytes);

        // Comparing the reserved bytes as the implementation should copy those
        // out without modifications for forward compatibility.
        assert_eq!(request.0.key_name, 1);
        assert_eq!(request.0.key_policy, 2);
        assert_eq!(request.0.isv_svn, 3);
        assert_eq!(request.0.reserved1, 4);
        assert_eq!(request.0.cpu_svn.svn, [5u8; SGX_CPUSVN_SIZE]);
        assert_eq!(request.0.attribute_mask.flags, 6);
        assert_eq!(request.0.attribute_mask.xfrm, 7);
        assert_eq!(request.0.key_id.id, [8u8; SGX_KEYID_SIZE]);
        assert_eq!(request.0.misc_mask, 9);
        assert_eq!(request.0.config_svn, 10);
        assert_eq!(request.0.reserved2, [11u8; SGX_KEY_REQUEST_RESERVED2_BYTES]);
    }

    #[test]
    fn key_request_from_bytes_2() {
        let bytes = key_request_to_bytes(request_2());
        let request = KeyRequest::from(&bytes);

        // Comparing the reserved bytes as the implementation should copy those
        // out without modifications for forward compatibility.
        assert_eq!(request.0.key_name, 21);
        assert_eq!(request.0.key_policy, 22);
        assert_eq!(request.0.isv_svn, 23);
        assert_eq!(request.0.reserved1, 24);
        assert_eq!(request.0.cpu_svn.svn, [25u8; SGX_CPUSVN_SIZE]);
        assert_eq!(request.0.attribute_mask.flags, 26);
        assert_eq!(request.0.attribute_mask.xfrm, 27);
        assert_eq!(request.0.key_id.id, [28u8; SGX_KEYID_SIZE]);
        assert_eq!(request.0.misc_mask, 29);
        assert_eq!(request.0.config_svn, 210);
        assert_eq!(
            request.0.reserved2,
            [211u8; SGX_KEY_REQUEST_RESERVED2_BYTES]
        );
    }
}
