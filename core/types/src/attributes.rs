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
    pub fn set_flags(mut self, flags: AttributeFlags) -> Self {
        self.0.flags = flags.bits();
        self
    }

    /// Set the extended features request mask (xfrm)
    ///
    /// # Arguments
    ///
    /// * `features_mask` - The mask to be set to the `xfrm` in the attributes
    pub fn set_extended_features_mask(mut self, features_mask: ExtendedFeatureRequestMask) -> Self {
        self.0.xfrm = features_mask.bits();
        self
    }
}

impl Display for Attributes {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match AttributeFlags::from_bits(self.0.flags) {
            Some(flags) => {
                if flags.is_empty() {
                    write!(f, "Flags: (none)")?
                } else {
                    write!(f, "Flags: {}", flags)?
                }
            }
            None => write!(f, "Flags: (none)")?,
        }
        match ExtendedFeatureRequestMask::from_bits(self.0.xfrm) {
            Some(xfrm) => {
                if xfrm.is_empty() {
                    write!(f, " Xfrm: (none)")?
                } else {
                    write!(f, " Xfrm: {}", xfrm)?
                }
            }
            None => write!(f, " Xfrm: (none)")?,
        }

        Ok(())
    }
}

impl Display for AttributeFlags {
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

impl Display for ExtendedFeatureRequestMask {
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
    /// Attribute flags of an enclave
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd)]
    pub struct AttributeFlags: u64 {
        /// If set, then the enclave is initialized
        const INITTED = SGX_FLAGS_INITTED as u64;
        /// If set, then the enclave is debug
        const DEBUG = SGX_FLAGS_DEBUG as u64;
        /// If set, then the enclave is 64 bit
        const MODE_64BIT = SGX_FLAGS_MODE64BIT as u64;
        /// If set, then the enclave has access to provision key
        const PROVISION_KEY = SGX_FLAGS_PROVISION_KEY as u64;
        /// If set, then the enclave has access to EINIT token key
        const EINIT_TOKEN_KEY = SGX_FLAGS_EINITTOKEN_KEY as u64;
        /// If set, then the enclave uses KSS(Key Separation and Sharing)
        const KSS = SGX_FLAGS_KSS as u64;
        /// BIT[55-48] will not be checked */
        const NON_CHECK_BITS = SGX_FLAGS_NON_CHECK_BITS;
        /// Value used by `sgx_seal_data()`. See `attribute_mask` description in
        /// <https://download.01.org/intel-sgx/sgx-linux/2.17.1/docs/Intel_SGX_Developer_Reference_Linux_2.17.1_Open_Source.pdf#%5B%7B%22num%22%3A331%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C94.5%2C733.5%2C0%5D>
        const SEALED_DATA = 0xFF0000000000000B;
    }

    /// Extended feature request mask (XFRM) of an enclave
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd)]
    pub struct ExtendedFeatureRequestMask: u64 {
        /// Legacy features which includes the basic feature bits required by SGX, x87 state(0x01) and SSE state(0x02)
        const LEGACY = SGX_XFRM_LEGACY as u64;
        /// AVX(Advanced Vector Extensions) which includes AVX state(0x04)
        /// and SSE state(0x02) required by AVX
        const AVX = SGX_XFRM_AVX as u64;
        /// AVX-512 (Advanced Vector Extensions, 512 bit) which includes AVX state(0x04)
        /// and SSE state(0x02) required by AVX
        const AVX_512 = SGX_XFRM_AVX512 as u64;
        /// MPX(Memory Protection Extensions) - not supported
        const MPX = SGX_XFRM_MPX as u64;
        /// PKRU(Protection Keys Register Userspace) state
        const PKRU = SGX_XFRM_PKRU as u64;
        /// AMX(Advanced Matrix Extensions), including XTILEDATA(0x40000) and XTILECFG(0x20000)
        const AMX = SGX_XFRM_LEGACY as u64;
        /// Reserved for future flags.
        const RESERVED = (!(Self::LEGACY.bits() | Self::AVX.bits() | Self::AVX_512.bits() | Self::PKRU.bits() | Self::AMX.bits()));
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
        inited_debug_legacy = { AttributeFlags::INITTED | AttributeFlags::DEBUG, ExtendedFeatureRequestMask::LEGACY },
        mode_64_legacy_avx = { AttributeFlags::MODE_64BIT, ExtendedFeatureRequestMask::LEGACY | ExtendedFeatureRequestMask::AVX },
    )]
    fn attributes_builder(flags: AttributeFlags, transform: ExtendedFeatureRequestMask) {
        let attributes = Attributes::default()
            .set_flags(flags)
            .set_extended_features_mask(transform);
        assert_eq!(attributes.0.flags, flags.bits());
        assert_eq!(attributes.0.xfrm, transform.bits());
    }

    #[test]
    fn attributes_display() {
        let flag1 = AttributeFlags::INITTED;
        let flag2 = AttributeFlags::DEBUG;
        let flag3 = AttributeFlags::MODE_64BIT;
        let flags = flag1 | flag2 | flag3;

        let xfrm1 = ExtendedFeatureRequestMask::LEGACY;
        let xfrm2 = ExtendedFeatureRequestMask::AVX;
        let xfrm = xfrm1 | xfrm2;
        let attributes = Attributes::default()
            .set_flags(flags)
            .set_extended_features_mask(xfrm);

        let display_string = format!("{}", attributes);
        let expected = format!("Flags: {flag1} | {flag2} | {flag3} Xfrm: {xfrm1} | {xfrm2}",);

        assert_eq!(display_string, expected);
    }

    #[test]
    fn attributes_display_all_flags_no_xfrm() {
        let flag1 = AttributeFlags::INITTED;
        let flag2 = AttributeFlags::DEBUG;
        let flag3 = AttributeFlags::PROVISION_KEY;
        let flag4 = AttributeFlags::EINIT_TOKEN_KEY;
        let flag5 = AttributeFlags::KSS;
        let flag6 = AttributeFlags::NON_CHECK_BITS;
        let flags = flag1 | flag2 | flag3 | flag4 | flag5 | flag6;

        let attributes = Attributes::default().set_flags(flags);

        let display_string = format!("{}", attributes);
        let expected = format!(
            "Flags: {flag1} | {flag2} | {flag3} | {flag4} | {flag5} | {flag6} Xfrm: (none)",
        );

        assert_eq!(display_string, expected);
    }

    #[test]
    fn attributes_display_no_flags() {
        let xfrm1 = ExtendedFeatureRequestMask::LEGACY;
        let xfrm2 = ExtendedFeatureRequestMask::AVX;
        let xfrm = xfrm1 | xfrm2;
        let attributes = Attributes::default().set_extended_features_mask(xfrm);

        let display_string = format!("{}", attributes);
        let expected = format!("Flags: (none) Xfrm: {xfrm1} | {xfrm2}",);

        assert_eq!(display_string, expected);
    }

    #[test]
    fn miscellaneous_select_display() {
        let inner = 18983928;
        let miscellaneous_select = MiscellaneousSelect::from(inner);

        let display_string = format!("{miscellaneous_select}");
        let expected_string = "0x0121_ABF8";

        assert_eq!(display_string, expected_string);
    }
}
