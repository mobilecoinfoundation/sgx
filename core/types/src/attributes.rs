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
        self.is_flag_set(Flags::XFRM_LEGACY.bits())
    }

    fn is_xfrm_avx(&self) -> bool {
        self.is_flag_set(Flags::XFRM_AVX.bits())
    }

    fn is_xfrm_avx512(&self) -> bool {
        self.is_flag_set(Flags::XFRM_AVX512.bits())
    }

    fn is_xfrm_mpx(&self) -> bool {
        self.is_flag_set(Flags::XFRM_MPX.bits())
    }

    fn is_xfrm_pkru(&self) -> bool {
        self.is_flag_set(Flags::XFRM_PKRU.bits())
    }

    fn is_xfrm_amx(&self) -> bool {
        self.is_flag_set(Flags::XFRM_AMX.bits())
    }

    fn is_xfrm_reserved(&self) -> bool {
        self.is_flag_set(Flags::XFRM_RESERVED.bits())
    }

    fn is_flag_set(&self, flag: u64) -> bool {
        (self.0.flags & flag) != 0
    }
}

impl Display for Attributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "The following Attribute flags are set: ")?;
        if self.is_initted() {
            write!(f, "INITTED")?;
            write!(f, ", ")?;
        }
        if self.is_debug() {
            write!(f, "DEBUG")?;
            write!(f, ", ")?;
        }
        if self.is_mode64() {
            write!(f, "MODE64BIT")?;
            write!(f, ", ")?;
        }
        if self.is_provision_key() {
            write!(f, "PROVISION_KEY")?;
            write!(f, ", ")?;
        }
        if self.is_einitotken_key() {
            write!(f, "EINITTOKEN_KEY")?;
            write!(f, ", ")?;
        }
        if self.is_kss() {
            write!(f, "KSS")?;
            write!(f, ", ")?;
        }
        if self.is_non_check_bits() {
            write!(f, "NON_CHECK_BITS")?;
            write!(f, ", ")?;
        }
        if self.is_xfrm_legacy() {
            write!(f, "XFRM_LEGACY")?;
            write!(f, ", ")?;
        }
        if self.is_xfrm_avx() {
            write!(f, "XFRM_AVX")?;
            write!(f, ", ")?;
        }
        if self.is_xfrm_avx512() {
            write!(f, "XFRM_AVX512")?;
            write!(f, ", ")?;
        }
        if self.is_xfrm_mpx() {
            write!(f, "XFRM_MPX")?;
            write!(f, ", ")?;
        }
        if self.is_xfrm_pkru() {
            write!(f, "XFRM_PKRU")?;
            write!(f, ", ")?;
        }
        if self.is_xfrm_amx() {
            write!(f, "XFRM_AMX")?;
            write!(f, ", ")?;
        }
        if self.is_xfrm_reserved() {
            write!(f, "XFRM_RESERVED")?;
            write!(f, ", ")?;
        }

        Ok(())
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
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
        /// Legacy XFRM which includes the basic feature bits required by SGX, x87 state(0x01) and SSE state(0x02)
        const XFRM_LEGACY = 0x0000000000000003;
        /// AVX XFRM which includes AVX state(0x04) and SSE state(0x02) required by AVX
        const XFRM_AVX = 0x0000000000000006;
        /// AVX-512 XFRM
        const XFRM_AVX512 = 0x00000000000000E6;
        /// MPX XFRM - not supported
        const XFRM_MPX = 0x0000000000000018;
        /// PKRU state
        const XFRM_PKRU = 0x0000000000000200;
        /// AMX XFRM, including XTILEDATA(0x40000) and XTILECFG(0x20000)
        const XFRM_AMX = 0x0000000000060000;
        /// Reserved for future flags.
        const XFRM_RESERVED = (!(Self::XFRM_LEGACY.bits() | Self::XFRM_AVX.bits() | Self::XFRM_AVX512.bits() | Self::XFRM_PKRU.bits() | Self::XFRM_AMX.bits()));
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
        let flags = Flags::INITTED
            | Flags::DEBUG
            | Flags::MODE64BIT;
        let attributes = Attributes::default().set_flags(flags.bits());

        let display_string = format!("{}", attributes);
        let expected = format!(
            "The following Attribute flags are set: {}, {}, {}, {}, {}, {}, ",
            "INITTED",
            "DEBUG",
            "MODE64BIT",
            // These flags are set by default when the above flags are set.
            "XFRM_LEGACY",
            "XFRM_AVX",
            "XFRM_AVX512",
        );

        assert_eq!(display_string, expected);
    }
}
