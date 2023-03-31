// Copyright (c) 2022-2023 The MobileCoin Foundation

//! SGX Attributes types

use crate::{impl_newtype, impl_newtype_no_display};
use bitflags::bitflags;
use core::fmt::{Display, Formatter};
use mc_sgx_core_sys_types::{sgx_attributes_t, sgx_misc_attribute_t, sgx_misc_select_t};

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

    fn is_initted(&self) -> bool {
        self.is_flag_set(Flags::INITTED.bits())
    }

    fn is_debug(&self) -> bool {
        self.is_flag_set(Flags::DEBUG.bits())
    }

    fn is_mode64(&self) -> bool {
        self.is_flag_set(Flags::MODE64BIT.bits())
    }

    fn is_provision_key(&self) -> bool {
        self.is_flag_set(Flags::PROVISION_KEY.bits())
    }

    fn is_einitotken_key(&self) -> bool {
        self.is_flag_set(Flags::EINITTOKEN_KEY.bits())
    }

    fn is_kss(&self) -> bool {
        self.is_flag_set(Flags::KSS.bits())
    }

    fn is_non_check_bits(&self) -> bool {
        self.is_flag_set(Flags::NON_CHECK_BITS.bits())
    }

    fn is_xfrm_legacy(&self) -> bool {
        self.is_flag_set(Xfrm::LEGACY.bits())
    }

    fn is_xfrm_avx(&self) -> bool {
        self.is_flag_set(Xfrm::AVX.bits())
    }

    fn is_xfrm_avx512(&self) -> bool {
        self.is_flag_set(Xfrm::AVX512.bits())
    }

    fn is_xfrm_mpx(&self) -> bool {
        self.is_flag_set(Xfrm::MPX.bits())
    }

    fn is_xfrm_pkru(&self) -> bool {
        self.is_flag_set(Xfrm::PKRU.bits())
    }

    fn is_xfrm_amx(&self) -> bool {
        self.is_flag_set(Xfrm::AMX.bits())
    }

    fn is_xfrm_reserved(&self) -> bool {
        self.is_flag_set(Xfrm::RESERVED.bits())
    }

    fn is_flag_set(&self, flag: u64) -> bool {
        (self.0.flags & flag) != 0
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
    #[derive(Clone, PartialOrd, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Flags: u64 {
        /// If set, then the enclave is initialized
        const INITTED = 0x0000000000000001;
        /// If set, then the enclave is debug
        const DEBUG = 0x0000000000000002;
        /// If set, then the enclave is 64 bit
        const MODE64BIT = 0x0000000000000004;
        /// set, then the enclave has access to provision key
        const PROVISION_KEY = 0x0000000000000010;
        /// If set, then the enclave has access to EINITTOKEN key
        const EINITTOKEN_KEY = 0x0000000000000020;
        /// If set enclave uses KSS
        const KSS = 0x0000000000000080;
        /// BIT[55-48] will not be checked */
        const NON_CHECK_BITS = 0x00FF000000000000;
    }

    #[derive(Clone, PartialOrd, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Xfrm: u64 {
        /// Legacy XFRM which includes the basic feature bits required by SGX, x87 state(0x01) and SSE state(0x02)
        const LEGACY = 0x0000000000000003;
        /// AVX XFRM which includes AVX state(0x04) and SSE state(0x02) required by AVX
        const AVX = 0x0000000000000006;
        /// AVX-512 XFRM
        const AVX512 = 0x00000000000000E6;
        /// MPX XFRM - not supported
        const MPX = 0x0000000000000018;
        /// PKRU state
        const PKRU = 0x0000000000000200;
        /// AMX XFRM, including XTILEDATA(0x40000) and XTILECFG(0x20000)
        const AMX = 0x0000000000060000;
        /// Reserved for future flags.
        const RESERVED = (!(Self::LEGACY.bits() | Self::AVX.bits() | Self::AVX512.bits() | Self::PKRU.bits() | Self::AMX.bits()));
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
    use mc_sgx_core_sys_types::SGX_XFRM_AMX;
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
    fn attriutes_display() {
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
}
