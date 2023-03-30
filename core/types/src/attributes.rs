// Copyright (c) 2022-2023 The MobileCoin Foundation

//! SGX Attributes types

use core::fmt::{Display, Formatter};
use bitflags::bitflags;
use crate::impl_newtype;
use mc_sgx_core_sys_types::{sgx_attributes_t, SGX_CONFIGID_SIZE, sgx_misc_attribute_t, sgx_misc_select_t};

/// Attributes of the enclave
#[repr(transparent)]
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq, Copy)]
pub struct Attributes(sgx_attributes_t);
impl_newtype! {
    Attributes, sgx_attributes_t;
}

impl Attributes {
    /// Set the `flags` for the attributes
    ///
    /// # Arguments
    ///
    /// * `flags` - The flags to be set in the attributes
    pub fn set_flags(mut self, flags: u64) -> Self {
        self.0.flags = flags;
        self
    }

    /// Set the extended features request mask (xfrm)
    ///
    /// # Arguments
    ///
    /// * `features_mask` - The mask to be set to the `xfrm` in the attributes
    pub fn set_extended_features_mask(mut self, features_mask: u64) -> Self {
        self.0.xfrm = features_mask;
        self
    }
}

impl Display for Attributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self
    }
}

bitflags! {
    /// Revocation cause flags
    #[derive(Deserialize, Serialize)]
    pub struct AttributeFlags: u64 {
        /// If set, then the enclave is initialized
        const SGX_FLAGS_INITTED = 0x0000000000000001;
        /// If set, then the enclave is debug
        const SGX_FLAGS_DEBUG   = 0x0000000000000002;
        /// If set, then the enclave is 64 bit
        const SGX_FLAGS_MODE64BIT      = 0x0000000000000004;
        /// set, then the enclave has access to provision key
        const SGX_FLAGS_PROVISION_KEY  0x0000000000000010ULL;
#define SGX_FLAGS_EINITTOKEN_KEY 0x0000000000000020ULL     /* If set, then the enclave has access to EINITTOKEN key */
#define SGX_FLAGS_KSS            0x0000000000000080ULL     /* If set enclave uses KSS */
#define SGX_FLAGS_NON_CHECK_BITS 0x00FF000000000000ULL     /* BIT[55-48] will not be checked */
#define SGX_XFRM_LEGACY          0x0000000000000003ULL     /* Legacy XFRM which includes the basic feature bits required by SGX, x87 state(0x01) and SSE state(0x02) */
#define SGX_XFRM_AVX             0x0000000000000006ULL     /* AVX XFRM which includes AVX state(0x04) and SSE state(0x02) required by AVX */
#define SGX_XFRM_AVX512          0x00000000000000E6ULL     /* AVX-512 XFRM */
#define SGX_XFRM_MPX             0x0000000000000018ULL     /* MPX XFRM - not supported */
#define SGX_XFRM_PKRU            0x0000000000000200ULL     /* PKRU state */
#define SGX_XFRM_AMX             0x0000000000060000ULL     /* AMX XFRM, including XTILEDATA(0x40000) and XTILECFG(0x20000) */
    }
}

/// Miscellaneous select bits for target enclave. Reserved for future extension.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
pub struct MiscellaneousSelect(sgx_misc_select_t);

impl_newtype! {
    MiscellaneousSelect, sgx_misc_select_t;
}

/// Miscellaneous attributes and select bits for target enclave.
#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MiscellaneousAttribute(sgx_misc_attribute_t);

impl_newtype! {
    MiscellaneousAttribute, sgx_misc_attribute_t;
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use yare::parameterized;

    #[test]
    fn sgx_attributes_to_attributes() {
        let sgx_attributes = sgx_attributes_t { flags: 1, xfrm: 2 };
        let attributes: Attributes = sgx_attributes.into();
        assert_eq!(attributes.0, sgx_attributes);
    }

    #[test]
    fn attributes_to_sgx_attributes() {
        let attributes = Attributes(sgx_attributes_t { flags: 9, xfrm: 12 });
        let sgx_attributes: sgx_attributes_t = attributes.into();
        assert_eq!(sgx_attributes, sgx_attributes_t { flags: 9, xfrm: 12 });
    }

    #[parameterized(
    three_five = { 3, 5 },
    four_nine = { 4, 9 },
    )]
    fn attributes_builder(flags: u64, transform: u64) {
        let attributes = Attributes::default()
            .set_flags(flags)
            .set_extended_features_mask(transform);
        assert_eq!(attributes.0.flags, flags);
        assert_eq!(attributes.0.xfrm, transform);
    }
}
