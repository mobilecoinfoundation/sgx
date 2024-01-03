// Copyright (c) 2022-2024 The MobileCoin Foundation

//! SGX Attributes types

use crate::{impl_newtype, impl_newtype_no_display};
use bitflags::{bitflags, Flags};
use core::fmt::{Display, Formatter};
use core::ops::BitAnd;
use mc_sgx_core_sys_types::{
    sgx_attributes_t, sgx_misc_attribute_t, sgx_misc_select_t, SGX_FLAGS_AEX_NOTIFY,
    SGX_FLAGS_DEBUG, SGX_FLAGS_EINITTOKEN_KEY, SGX_FLAGS_INITTED, SGX_FLAGS_KSS,
    SGX_FLAGS_MODE64BIT, SGX_FLAGS_NON_CHECK_BITS, SGX_FLAGS_PROVISION_KEY, SGX_XFRM_AMX,
    SGX_XFRM_AVX, SGX_XFRM_AVX512, SGX_XFRM_LEGACY, SGX_XFRM_MPX, SGX_XFRM_PKRU,
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

            None => {
                write!(f, "Flags: ")?;
                mc_sgx_util::fmt_hex(&self.0.flags.to_be_bytes(), f)?;
            }
        }
        match ExtendedFeatureRequestMask::from_bits(self.0.xfrm) {
            Some(xfrm) => {
                if xfrm.is_empty() {
                    write!(f, " Xfrm: (none)")?
                } else {
                    write!(f, " Xfrm: {}", xfrm)?
                }
            }
            None => {
                write!(f, " Xfrm: ")?;
                mc_sgx_util::fmt_hex(&self.0.xfrm.to_be_bytes(), f)?;
            }
        }

        Ok(())
    }
}

impl Display for AttributeFlags {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        format_bitflags(self, f)
    }
}

impl Display for ExtendedFeatureRequestMask {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        format_bitflags(self, f)
    }
}

/// Formats the provided bitflags as text
///
/// Any bits that aren't part of a contained flag will be formatted as a hex number.
///
/// Example output with two known flags and some bits that didn't pertain to a tag
///
///    FLAG1 | FLAG2 | 0x0000_0000_FF00_0000
///
fn format_bitflags<F: Flags>(bitflags: &F, f: &mut Formatter) -> core::fmt::Result
where
    F::Bits: Into<u64>,
{
    let mut separators = ::core::iter::once("").chain(::core::iter::repeat(" | "));
    let mut iter = bitflags.iter_names();
    for (name, _) in &mut iter {
        let separator = separators.next().expect("Separator should exist");
        write!(f, "{}", separator)?;
        write!(f, "{}", name)?;
    }

    let remaining = iter.remaining().bits();
    if remaining != bitflags::Bits::EMPTY {
        let separator = separators.next().expect("Separator should exist");
        write!(f, "{}", separator)?;
        mc_sgx_util::fmt_hex(&remaining.into().to_be_bytes(), f)?;
    }

    Ok(())
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
        /// If set, then the enclave enables AEX Notify
        const AEX_NOTIFY = SGX_FLAGS_AEX_NOTIFY as u64;
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
        const AMX = SGX_XFRM_AMX as u64;
        /// Reserved for future flags.
        const RESERVED = (!(Self::LEGACY.bits() | Self::AVX.bits() | Self::AVX_512.bits() | Self::PKRU.bits() | Self::AMX.bits()));
    }
}

/// When verifying a QE(quoting enclave) only some of the bits in
/// [`Attributes`] are looked at. These bits are indicated via a
/// provided mask of the same type.
impl BitAnd for Attributes {
    type Output = Attributes;

    fn bitand(self, rhs: Self) -> Self::Output {
        let flags = self.0.flags & rhs.0.flags;
        let xfrm = self.0.xfrm & rhs.0.xfrm;
        Attributes(sgx_attributes_t { flags, xfrm })
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

/// When verifying a QE(quoting enclave) only some of the bits in
/// [`MiscellaneousSelect`] are looked at. These bits are indicated via a
/// provided mask of the same type.
impl BitAnd for MiscellaneousSelect {
    type Output = MiscellaneousSelect;

    fn bitand(self, rhs: Self) -> Self::Output {
        MiscellaneousSelect(self.0 & rhs.0)
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
    use std::string::ToString;
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
        let xfrm = ExtendedFeatureRequestMask::LEGACY
            | ExtendedFeatureRequestMask::AVX
            | ExtendedFeatureRequestMask::AMX;
        let attributes = Attributes::default().set_extended_features_mask(xfrm);

        assert_eq!(
            attributes.to_string(),
            "Flags: (none) Xfrm: LEGACY | AVX | AMX"
        );
    }

    #[test]
    fn attributes_display_all_flag_bits_set() {
        let attributes = Attributes::from(sgx_attributes_t {
            flags: 0xFFFF_FFFF_FFFF_FFFF,
            xfrm: 0,
        });
        assert_eq!(
            attributes.to_string(),
            "Flags: 0xFFFF_FFFF_FFFF_FFFF Xfrm: (none)"
        );
    }

    #[test]
    fn attributes_display_unknown_xfrm_bits_set() {
        // Notice the MSB isn't set, this is because setting *all* the bits will
        // result in it picking up the RESERVED bits
        let attributes = Attributes::from(sgx_attributes_t {
            flags: 0,
            xfrm: 0x7FFF_FFFF_FFFF_FFFF,
        });
        assert_eq!(
            attributes.to_string(),
            "Flags: (none) Xfrm: LEGACY | AVX | AVX_512 | MPX | PKRU | AMX | 0x7FFF_FFFF_FFF9_FD00"
        );
    }

    #[test]
    fn miscellaneous_select_display() {
        let inner = 18983928;
        let miscellaneous_select = MiscellaneousSelect::from(inner);

        let display_string = format!("{miscellaneous_select}");
        let expected_string = "0x0121_ABF8";

        assert_eq!(display_string, expected_string);
    }

    #[parameterized(
        all_zeros = {0, 0, 0},
        all_ones = {0b1111_1111, 0b1111_1111, 0b1111_1111},
        ones_and_zeros_are_zeros = {0b1111_1111, 0, 0},
        lower_nybble_matches = {0b1010_1010, 0b0000_1010, 0b0000_1010},
        last_bit = {0b1111_1111, 0b0000_0001, 0b0000_0001},
        first_bit = {0b1111_1111, 0b1000_0000, 0b1000_0000},
    )]
    fn bitwise_and_miscellaneous_select(left: u32, right: u32, expected: u32) {
        let left = MiscellaneousSelect::from(left);
        let right = MiscellaneousSelect::from(right);
        let expected = MiscellaneousSelect::from(expected);
        assert_eq!(left & right, expected);
    }

    #[parameterized(
        all_zeros = {0, 0, 0},
        all_ones = {0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF},
        ones_and_zeros_are_zeros = {0xFFFF_FFFF_FFFF_FFFF, 0, 0},
        lower_byte_matches = {0xAAAA_AAAA_AAAA_AAAA, 0x5555_5555_5555_AAAA, 0x0000_0000_0000_AAAA},
        upper_byte_matches = {0xAAAA_AAAA_AAAA_AAAA, 0xAAAA_5555_5555_5555, 0xAAAA_0000_0000_0000},
        last_bit = {0x0000_0000_0000_0001, 0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_0000_0001},
        first_bit = {0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0000, 0x8000_0000_0000_0000},
    )]
    fn bitwise_and_attribute_flags(left: u64, right: u64, expected: u64) {
        // Build attributes from the base type because, the `AttributeFlags` will be limited based
        // on what we know to be defined, while the actual flags seen in practice could grow.
        // For example `AttributeFlags::from_bits(256)` will fail since the largest known bit is at
        // 128 but `Attributes(sgx_attributes_t { flags: 256, xfrm: 0 })` will work fine.
        let left = Attributes(sgx_attributes_t {
            flags: left,
            xfrm: 0,
        });
        let right = Attributes(sgx_attributes_t {
            flags: right,
            xfrm: 0,
        });
        let expected = Attributes(sgx_attributes_t {
            flags: expected,
            xfrm: 0,
        });
        assert_eq!(left & right, expected);
    }

    #[parameterized(
        all_zeros = {0, 0, 0},
        all_ones = {0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF},
        ones_and_zeros_are_zeros = {0xFFFF_FFFF_FFFF_FFFF, 0, 0},
        lower_byte_matches = {0x5555_5555_5555_AAAA, 0xAAAA_AAAA_AAAA_AAAA, 0x0000_0000_0000_AAAA},
        upper_byte_matches = {0xAAAA_5555_5555_5555, 0xAAAA_AAAA_AAAA_AAAA, 0xAAAA_0000_0000_0000},
        last_bit = {0xFFFF_FFFF_FFFF_FFFF, 0x0000_0000_0000_0001, 0x0000_0000_0000_0001},
        first_bit = {0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0000},
    )]
    fn bitwise_and_attribute_extended_feature_mask(left: u64, right: u64, expected: u64) {
        let left = Attributes(sgx_attributes_t {
            flags: 0,
            xfrm: left,
        });
        let right = Attributes(sgx_attributes_t {
            flags: 0,
            xfrm: right,
        });
        let expected = Attributes(sgx_attributes_t {
            flags: 0,
            xfrm: expected,
        });
        assert_eq!(left & right, expected);
    }
}
