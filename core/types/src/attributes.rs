// Copyright (c) 2022-2023 The MobileCoin Foundation

//! SGX Attributes types

use crate::{impl_newtype, impl_newtype_no_display};
use bitflags::bitflags;
use core::fmt::{Display, Formatter};
use mc_sgx_core_sys_types::{
    sgx_attributes_t, sgx_misc_attribute_t, sgx_misc_select_t, SGX_FLAGS_DEBUG,
    SGX_FLAGS_EINITTOKEN_KEY, SGX_FLAGS_INITTED, SGX_FLAGS_KSS, SGX_FLAGS_MODE64BIT,
    SGX_FLAGS_NON_CHECK_BITS, SGX_FLAGS_PROVISION_KEY, SGX_XFRM_AVX, SGX_XFRM_AVX512,
    SGX_XFRM_LEGACY, SGX_XFRM_MPX, SGX_XFRM_PKRU,
};

/// Attributes of the enclave
#[repr(transparent)]
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq, Copy)]
pub struct Attributes(sgx_attributes_t);
impl_newtype_no_display! {
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
        write!(f, "Flags: {}", Flags::from_bits(self.0.flags).unwrap())?;
        write!(f, " Xfrm: {}", Xfrm::from_bits(self.0.xfrm).unwrap())
    }
}

impl Display for Flags {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        for (idx, (name, flag)) in self.iter_names().enumerate() {
            if *self & flag == flag {
                if idx >= 1 {
                    write!(f, " | ")?;
                }
                write!(f, "{}", name)?;
            }
        }
        Ok(())
    }
}

impl Display for Xfrm {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        for (idx, (name, flag)) in self.iter_names().enumerate() {
            if *self & flag == flag {
                if idx >= 1 {
                    write!(f, " | ")?;
                }
                write!(f, "{}", name)?;
            }
        }

        Ok(())
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd)]
    pub struct Flags: u64 {
        /// If set, then the enclave is initialized
        const INITTED = SGX_FLAGS_INITTED as u64;
        /// If set, then the enclave is debug
        const DEBUG = SGX_FLAGS_DEBUG as u64;
        /// If set, then the enclave is 64 bit
        const MODE64BIT = SGX_FLAGS_MODE64BIT as u64;
        /// set, then the enclave has access to provision key
        const PROVISION_KEY = SGX_FLAGS_PROVISION_KEY as u64;
        /// If set, then the enclave has access to EINITTOKEN key
        const EINITTOKEN_KEY = SGX_FLAGS_EINITTOKEN_KEY as u64;
        /// If set enclave uses KSS
        const KSS = SGX_FLAGS_KSS as u64;
        /// BIT[55-48] will not be checked */
        const NON_CHECK_BITS = SGX_FLAGS_NON_CHECK_BITS;
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd)]
    pub struct Xfrm: u64 {
        /// Legacy XFRM which includes the basic feature bits required by SGX, x87 state(0x01) and SSE state(0x02)
        const LEGACY = SGX_XFRM_LEGACY as u64;
        /// AVX XFRM which includes AVX state(0x04) and SSE state(0x02) required by AVX
        const AVX = SGX_XFRM_AVX as u64;
        /// AVX-512 XFRM
        const AVX512 = SGX_XFRM_AVX512 as u64;
        /// MPX XFRM - not supported
        const MPX = SGX_XFRM_MPX as u64;
        /// PKRU state
        const PKRU = SGX_XFRM_PKRU as u64;
        /// AMX XFRM, including XTILEDATA(0x40000) and XTILECFG(0x20000)
        const AMX = SGX_XFRM_LEGACY as u64;
        /// Reserved for future flags.
        const RESERVED = (!(Self::LEGACY.bits() | Self::AVX.bits() | Self::AVX512.bits() | Self::PKRU.bits() | Self::AMX.bits()));
    }
}

/// Miscellaneous select bits for target enclave. Reserved for future extension.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
pub struct MiscellaneousSelect(sgx_misc_select_t);

impl_newtype_no_display! {
    MiscellaneousSelect, sgx_misc_select_t;
}

impl Display for MiscellaneousSelect {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        mc_sgx_util::fmt_hex(&self.0.to_be_bytes(), f)
    }
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
    use std::format;
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

    #[test]
    fn attributes_display() {
        let flag1 = Flags::INITTED;
        let flag2 = Flags::DEBUG;
        let flag3 = Flags::MODE64BIT;
        let flags = flag1 | flag2 | flag3;

        let xfrm1 = Xfrm::LEGACY;
        let xfrm2 = Xfrm::AVX;
        let xfrm = xfrm1 | xfrm2;
        let attributes = Attributes::default()
            .set_flags(flags.bits())
            .set_extended_features_mask(xfrm.bits());

        let display_string = format!("{}", attributes);
        let expected = format!(
            "Flags: {} | {} | {} Xfrm: {} | {}",
            flag1, flag2, flag3, xfrm1, xfrm2
        );

        assert_eq!(display_string, expected);
    }

    #[test]
    fn attributes_display_all_flags_no_xfrm() {
        let flag1 = Flags::INITTED;
        let flag2 = Flags::DEBUG;
        let flag3 = Flags::PROVISION_KEY;
        let flag4 = Flags::EINITTOKEN_KEY;
        let flag5 = Flags::KSS;
        let flag6 = Flags::NON_CHECK_BITS;
        let flags = flag1 | flag2 | flag3 | flag4 | flag5 | flag6;

        let attributes = Attributes::default().set_flags(flags.bits());

        let display_string = format!("{}", attributes);
        let expected = format!(
            "Flags: {} | {} | {} | {} | {} | {} Xfrm: ",
            flag1, flag2, flag3, flag4, flag5, flag6,
        );

        assert_eq!(display_string, expected);
    }

    #[test]
    fn miscellaneous_select_display() {
        let sgx_misc_select_t = 18983928;
        let miscellaneous_select = MiscellaneousSelect::from(sgx_misc_select_t);

        let display_string = format!("{}", miscellaneous_select);
        let expected_string = format!("0x0121_ABF8");

        assert_eq!(display_string, expected_string);
    }
}
