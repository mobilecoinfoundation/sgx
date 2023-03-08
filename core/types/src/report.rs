// Copyright (c) 2022-2023 The MobileCoin Foundation
//! SGX Report

use crate::{
    config_id::ConfigId, impl_newtype_for_bytestruct, key_request::KeyId, new_type_accessors_impls,
    Attributes, ConfigSvn, CpuSvn, FfiError, IsvSvn, MiscellaneousSelect, MrEnclave, MrSigner,
};
use core::ops::BitAnd;
use mc_sgx_core_sys_types::{
    sgx_isvext_prod_id_t, sgx_isvfamily_id_t, sgx_mac_t, sgx_prod_id_t, sgx_report_body_t,
    sgx_report_data_t, sgx_report_t, SGX_CONFIGID_SIZE, SGX_CPUSVN_SIZE, SGX_HASH_SIZE,
    SGX_ISVEXT_PROD_ID_SIZE, SGX_ISV_FAMILY_ID_SIZE, SGX_REPORT_BODY_RESERVED1_BYTES,
    SGX_REPORT_BODY_RESERVED2_BYTES, SGX_REPORT_BODY_RESERVED3_BYTES,
    SGX_REPORT_BODY_RESERVED4_BYTES, SGX_REPORT_DATA_SIZE,
};
use nom::bytes::complete::take;
use nom::number::complete::{le_u16, le_u32, le_u64};

/// MAC
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct Mac(sgx_mac_t);

new_type_accessors_impls! {
    Mac, sgx_mac_t;
}

/// Report Data
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct ReportData(sgx_report_data_t);

impl_newtype_for_bytestruct! {
    ReportData, sgx_report_data_t, SGX_REPORT_DATA_SIZE, d;
}

/// There are times when only part of [`ReportData`] is of interest. [`BitAnd`]
/// allows clients to mask off the parts of [`ReportData`] that are not of
/// interest.
impl BitAnd for &ReportData {
    type Output = ReportData;

    fn bitand(self, rhs: Self) -> Self::Output {
        // NB: Due to use in verification, this must be constant time.
        let mut output = ReportData::default();
        for (i, (a, b)) in self.0.d.iter().zip(rhs.0.d.iter()).enumerate() {
            output.0.d[i] = a & b;
        }
        output
    }
}

impl BitAnd for ReportData {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        &self & &rhs
    }
}

/// ISV Family ID
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct FamilyId(sgx_isvfamily_id_t);

new_type_accessors_impls! {
    FamilyId, sgx_isvfamily_id_t;
}

/// Extended Product ID
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct ExtendedProductId(sgx_isvext_prod_id_t);

new_type_accessors_impls! {
    ExtendedProductId, sgx_isvext_prod_id_t;
}

/// ISV Product ID
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
#[repr(transparent)]
pub struct IsvProductId(sgx_prod_id_t);

new_type_accessors_impls! {
    IsvProductId, sgx_prod_id_t;
}

/// The main body of a report from SGX
#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct ReportBody(sgx_report_body_t);

impl ReportBody {
    /// The CPU SVN of this report
    pub fn cpu_svn(&self) -> CpuSvn {
        self.0.cpu_svn.into()
    }

    /// Miscellaneous Select values
    pub fn miscellaneous_select(&self) -> MiscellaneousSelect {
        self.0.misc_select.into()
    }

    /// The ISV extended product id
    pub fn isv_extended_product_id(&self) -> ExtendedProductId {
        self.0.isv_ext_prod_id.into()
    }

    /// The attributes
    pub fn attributes(&self) -> Attributes {
        self.0.attributes.into()
    }

    /// The MRENCLAVE measurement
    pub fn mr_enclave(&self) -> MrEnclave {
        self.0.mr_enclave.into()
    }

    /// The MRSIGNER measurement
    pub fn mr_signer(&self) -> MrSigner {
        self.0.mr_signer.into()
    }

    /// The Config ID
    pub fn config_id(&self) -> ConfigId {
        self.0.config_id.into()
    }

    /// The ISV product ID
    pub fn isv_product_id(&self) -> IsvProductId {
        self.0.isv_prod_id.into()
    }

    /// The ISV SVN
    pub fn isv_svn(&self) -> IsvSvn {
        self.0.isv_svn.into()
    }

    /// The Config SVN
    pub fn config_svn(&self) -> ConfigSvn {
        self.0.config_svn.into()
    }

    /// The ISV Family ID
    pub fn isv_family_id(&self) -> FamilyId {
        self.0.isv_family_id.into()
    }

    /// The report data
    pub fn report_data(&self) -> ReportData {
        self.0.report_data.into()
    }
}

new_type_accessors_impls! {
    ReportBody, sgx_report_body_t;
}

impl TryFrom<&[u8]> for ReportBody {
    type Error = FfiError;

    fn try_from(bytes: &[u8]) -> Result<Self, FfiError> {
        let mut body = Self::default();

        let (bytes, cpu_svn) = take(SGX_CPUSVN_SIZE)(bytes)?;
        body.0.cpu_svn = CpuSvn::try_from(cpu_svn)?.into();

        let (bytes, misc_select) = le_u32(bytes)?;
        body.0.misc_select = misc_select;

        let (bytes, reserved1) = take(SGX_REPORT_BODY_RESERVED1_BYTES)(bytes)?;
        body.0.reserved1.as_mut().copy_from_slice(reserved1);

        let (bytes, extended_prod_id) = take(SGX_ISVEXT_PROD_ID_SIZE)(bytes)?;
        body.0
            .isv_ext_prod_id
            .as_mut()
            .copy_from_slice(extended_prod_id);

        let (bytes, flags) = le_u64(bytes)?;
        body.0.attributes.flags = flags;

        let (bytes, xfrm) = le_u64(bytes)?;
        body.0.attributes.xfrm = xfrm;

        let (bytes, mr_enclave) = take(SGX_HASH_SIZE)(bytes)?;
        body.0.mr_enclave = MrEnclave::try_from(mr_enclave)?.into();

        let (bytes, reserved2) = take(SGX_REPORT_BODY_RESERVED2_BYTES)(bytes)?;
        body.0.reserved2.as_mut().copy_from_slice(reserved2);

        let (bytes, mr_signer) = take(SGX_HASH_SIZE)(bytes)?;
        body.0.mr_signer = MrSigner::try_from(mr_signer)?.into();

        let (bytes, reserved3) = take(SGX_REPORT_BODY_RESERVED3_BYTES)(bytes)?;
        body.0.reserved3.as_mut().copy_from_slice(reserved3);

        let (bytes, config_id) = take(SGX_CONFIGID_SIZE)(bytes)?;
        body.0.config_id.as_mut().copy_from_slice(config_id);

        let (bytes, isv_prod_id) = le_u16(bytes)?;
        body.0.isv_prod_id = isv_prod_id;

        let (bytes, isv_svn) = le_u16(bytes)?;
        body.0.isv_svn = isv_svn;

        let (bytes, config_svn) = le_u16(bytes)?;
        body.0.config_svn = config_svn;

        let (bytes, reserved4) = take(SGX_REPORT_BODY_RESERVED4_BYTES)(bytes)?;
        body.0.reserved4.as_mut().copy_from_slice(reserved4);

        let (bytes, isv_family_id) = take(SGX_ISV_FAMILY_ID_SIZE)(bytes)?;
        body.0.isv_family_id.as_mut().copy_from_slice(isv_family_id);

        let (_, report_data) = take(SGX_REPORT_DATA_SIZE)(bytes)?;
        body.0.report_data = ReportData::try_from(report_data)?.into();

        Ok(body)
    }
}

/// An enclave Report
#[repr(transparent)]
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct Report(sgx_report_t);

impl Report {
    /// The report body
    pub fn body(&self) -> ReportBody {
        self.0.body.into()
    }

    /// The key ID
    pub fn key_id(&self) -> KeyId {
        self.0.key_id.into()
    }

    /// The MAC
    pub fn mac(&self) -> Mac {
        self.0.mac.into()
    }
}

new_type_accessors_impls! {
    Report, sgx_report_t;
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use crate::{key_request::KeyId, MrEnclave, MrSigner};
    use core::{mem, slice};
    use mc_sgx_core_sys_types::{SGX_KEYID_SIZE, SGX_MAC_SIZE};
    use yare::parameterized;

    fn report_body_1() -> sgx_report_body_t {
        sgx_report_body_t {
            cpu_svn: CpuSvn::from([1u8; CpuSvn::SIZE]).into(),
            misc_select: 2,
            reserved1: [3u8; SGX_REPORT_BODY_RESERVED1_BYTES],
            isv_ext_prod_id: [4u8; SGX_ISVEXT_PROD_ID_SIZE],
            attributes: Attributes::default()
                .set_flags(5)
                .set_extended_features_mask(6)
                .into(),
            mr_enclave: MrEnclave::from([7u8; MrEnclave::SIZE]).into(),
            reserved2: [8u8; SGX_REPORT_BODY_RESERVED2_BYTES],
            mr_signer: MrSigner::from([9u8; MrSigner::SIZE]).into(),
            reserved3: [10u8; SGX_REPORT_BODY_RESERVED3_BYTES],
            config_id: [11u8; SGX_CONFIGID_SIZE],
            isv_prod_id: 12,
            isv_svn: 13,
            config_svn: 14,
            reserved4: [15u8; SGX_REPORT_BODY_RESERVED4_BYTES],
            isv_family_id: [16u8; SGX_ISV_FAMILY_ID_SIZE],
            report_data: sgx_report_data_t {
                d: [17u8; SGX_REPORT_DATA_SIZE],
            },
        }
    }

    fn report_body_2() -> sgx_report_body_t {
        sgx_report_body_t {
            cpu_svn: CpuSvn::from([12u8; CpuSvn::SIZE]).into(),
            misc_select: 22,
            reserved1: [32u8; SGX_REPORT_BODY_RESERVED1_BYTES],
            isv_ext_prod_id: [42u8; SGX_ISVEXT_PROD_ID_SIZE],
            attributes: Attributes::default()
                .set_flags(52)
                .set_extended_features_mask(62)
                .into(),
            mr_enclave: MrEnclave::from([72u8; MrEnclave::SIZE]).into(),
            reserved2: [82u8; SGX_REPORT_BODY_RESERVED2_BYTES],
            mr_signer: MrSigner::from([92u8; MrSigner::SIZE]).into(),
            reserved3: [102u8; SGX_REPORT_BODY_RESERVED3_BYTES],
            config_id: [112u8; SGX_CONFIGID_SIZE],
            isv_prod_id: 122,
            isv_svn: 132,
            config_svn: 142,
            reserved4: [152u8; SGX_REPORT_BODY_RESERVED4_BYTES],
            isv_family_id: [162u8; SGX_ISV_FAMILY_ID_SIZE],
            report_data: sgx_report_data_t {
                d: [172u8; SGX_REPORT_DATA_SIZE],
            },
        }
    }

    #[allow(unsafe_code)]
    fn report_body_to_bytes(body: sgx_report_body_t) -> [u8; mem::size_of::<sgx_report_body_t>()] {
        // SAFETY: This is a test only function. The size of `body` is used for
        // reinterpretation of `body` into a byte slice. The slice is copied
        // from prior to the leaving of this function ensuring the raw pointer
        // is not persisted.
        let alias_bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                &body as *const sgx_report_body_t as *const u8,
                mem::size_of::<sgx_report_body_t>(),
            )
        };
        let mut bytes: [u8; mem::size_of::<sgx_report_body_t>()] =
            [0; mem::size_of::<sgx_report_body_t>()];
        bytes.copy_from_slice(alias_bytes);
        bytes
    }

    #[test]
    fn default_report_body() {
        let body = ReportBody::default();
        assert_eq!(body.cpu_svn(), CpuSvn::default());
        assert_eq!(body.miscellaneous_select(), MiscellaneousSelect::default());
        assert_eq!(body.isv_extended_product_id(), ExtendedProductId::default());
        assert_eq!(body.attributes(), Attributes::default());
        assert_eq!(body.mr_enclave(), MrEnclave::default());
        assert_eq!(body.mr_signer(), MrSigner::default());
        assert_eq!(body.config_id(), ConfigId::default());
        assert_eq!(body.isv_product_id(), IsvProductId::default());
        assert_eq!(body.isv_svn(), IsvSvn::default());
        assert_eq!(body.config_svn(), ConfigSvn::default());
        assert_eq!(body.isv_family_id(), FamilyId::default());
        assert_eq!(body.report_data(), ReportData::default());
    }

    #[test]
    fn report_body_1_from_bytes() {
        let bytes = report_body_to_bytes(report_body_1());
        let body = ReportBody::try_from(bytes.as_slice()).unwrap();
        assert_eq!(body.cpu_svn(), CpuSvn::from([1u8; CpuSvn::SIZE]));
        assert_eq!(body.miscellaneous_select(), MiscellaneousSelect::from(2));
        assert_eq!(body.0.reserved1, [3u8; SGX_REPORT_BODY_RESERVED1_BYTES]);
        assert_eq!(
            body.isv_extended_product_id(),
            ExtendedProductId([4u8; SGX_ISVEXT_PROD_ID_SIZE])
        );
        assert_eq!(
            body.attributes(),
            Attributes::default()
                .set_flags(5)
                .set_extended_features_mask(6)
        );
        assert_eq!(body.mr_enclave(), MrEnclave::from([7u8; SGX_HASH_SIZE]));
        assert_eq!(body.0.reserved2, [8u8; SGX_REPORT_BODY_RESERVED2_BYTES]);
        assert_eq!(body.mr_signer(), MrSigner::from([9u8; SGX_HASH_SIZE]));
        assert_eq!(body.0.reserved3, [10u8; SGX_REPORT_BODY_RESERVED3_BYTES]);
        assert_eq!(body.config_id(), ConfigId::from([11u8; SGX_CONFIGID_SIZE]));
        assert_eq!(body.isv_product_id(), IsvProductId(12));
        assert_eq!(body.isv_svn(), IsvSvn::from(13));
        assert_eq!(body.config_svn(), ConfigSvn::from(14));
        assert_eq!(body.0.reserved4, [15u8; SGX_REPORT_BODY_RESERVED4_BYTES]);
        assert_eq!(
            body.isv_family_id(),
            FamilyId([16u8; SGX_ISV_FAMILY_ID_SIZE])
        );
        assert_eq!(
            body.report_data(),
            ReportData(sgx_report_data_t {
                d: [17u8; SGX_REPORT_DATA_SIZE]
            })
        );
    }

    #[test]
    fn report_body_fails_when_not_enough_bytes() {
        let bytes = report_body_to_bytes(report_body_1());
        assert_eq!(
            ReportBody::try_from(&bytes[1..]),
            Err(FfiError::InvalidInputLength)
        );
    }

    #[test]
    fn report_body_2_from_bytes() {
        let bytes = report_body_to_bytes(report_body_2());
        let body = ReportBody::try_from(bytes.as_slice()).unwrap();
        assert_eq!(body.cpu_svn(), CpuSvn::from([12u8; CpuSvn::SIZE]));
        assert_eq!(body.miscellaneous_select(), MiscellaneousSelect::from(22));
        assert_eq!(body.0.reserved1, [32u8; SGX_REPORT_BODY_RESERVED1_BYTES]);
        assert_eq!(
            body.isv_extended_product_id(),
            ExtendedProductId([42u8; SGX_ISVEXT_PROD_ID_SIZE])
        );
        assert_eq!(
            body.attributes(),
            Attributes::default()
                .set_flags(52)
                .set_extended_features_mask(62)
        );
        assert_eq!(body.mr_enclave(), MrEnclave::from([72u8; SGX_HASH_SIZE]));
        assert_eq!(body.0.reserved2, [82u8; SGX_REPORT_BODY_RESERVED2_BYTES]);
        assert_eq!(body.mr_signer(), MrSigner::from([92u8; SGX_HASH_SIZE]));
        assert_eq!(body.0.reserved3, [102u8; SGX_REPORT_BODY_RESERVED3_BYTES]);
        assert_eq!(body.config_id(), ConfigId::from([112u8; SGX_CONFIGID_SIZE]));
        assert_eq!(body.isv_product_id(), IsvProductId(122));
        assert_eq!(body.isv_svn(), IsvSvn::from(132));
        assert_eq!(body.config_svn(), ConfigSvn::from(142));
        assert_eq!(body.0.reserved4, [152u8; SGX_REPORT_BODY_RESERVED4_BYTES]);
        assert_eq!(
            body.isv_family_id(),
            FamilyId([162u8; SGX_ISV_FAMILY_ID_SIZE])
        );
        assert_eq!(
            body.report_data(),
            ReportData(sgx_report_data_t {
                d: [172u8; SGX_REPORT_DATA_SIZE]
            })
        );
    }
    #[test]
    fn report_from_sgx_report() {
        let mut body = ReportBody::default();
        body.0.isv_prod_id = 3;
        let sgx_report = sgx_report_t {
            body: body.clone().into(),
            key_id: KeyId::from([4u8; SGX_KEYID_SIZE]).into(),
            mac: [5u8; SGX_MAC_SIZE],
        };
        let report: Report = sgx_report.into();
        assert_eq!(report.body(), body);
        assert_eq!(report.key_id(), KeyId::from([4u8; SGX_KEYID_SIZE]));
        assert_eq!(report.mac(), Mac([5u8; SGX_MAC_SIZE]));
    }

    #[test]
    fn sgx_report_default() {
        let report = Report::default();
        assert_eq!(report.body(), ReportBody::default());
        assert_eq!(report.key_id(), KeyId::default());
        assert_eq!(report.mac(), Mac::default());
    }

    #[parameterized(
        all_zeros = {&[0u8; SGX_REPORT_DATA_SIZE], &[0u8; SGX_REPORT_DATA_SIZE], &[0u8; SGX_REPORT_DATA_SIZE]},
        all_ones = {&[0b1111_1111u8; SGX_REPORT_DATA_SIZE], &[0b1111_1111u8; SGX_REPORT_DATA_SIZE], &[0b1111_1111u8; SGX_REPORT_DATA_SIZE]},
        ones_and_zeros_are_zeros = {&[0b1111_1111u8; SGX_REPORT_DATA_SIZE], &[0u8; SGX_REPORT_DATA_SIZE], &[0u8; SGX_REPORT_DATA_SIZE]},
        lower_nybble_matches = {&[0b1010_1010u8; SGX_REPORT_DATA_SIZE], &[0b0000_1010u8; SGX_REPORT_DATA_SIZE], &[0b0000_1010u8; SGX_REPORT_DATA_SIZE]},
    )]
    fn bitwise_and_report_data(left: &[u8], right: &[u8], expected: &[u8]) {
        let left = ReportData::try_from(left).expect("Expected valid left ReportData");
        let right = ReportData::try_from(right).expect("Expected valid right ReportData");
        let expected = ReportData::try_from(expected).expect("Expected valid expected ReportData");
        assert_eq!(left & right, expected);
    }

    #[test]
    fn bitwise_and_report_data_looks_at_first_byte() {
        let mut left = [1u8; SGX_REPORT_DATA_SIZE];
        let mut right = [0u8; SGX_REPORT_DATA_SIZE];
        let mut expected = [0u8; SGX_REPORT_DATA_SIZE];

        // Keeping the first byte different than the other bytes to ensure it is
        // independent from the other bytes in the array.
        left[0] = 0b1111_0000u8;
        right[0] = 0b1111_0000u8;
        expected[0] = 0b1111_0000u8;
        assert_eq!(
            ReportData::from(left) & ReportData::from(right),
            ReportData::from(expected)
        );
    }

    #[test]
    fn bitwise_and_report_data_looks_at_last_byte() {
        let mut left = [1u8; SGX_REPORT_DATA_SIZE];
        let mut right = [0u8; SGX_REPORT_DATA_SIZE];
        let mut expected = [0u8; SGX_REPORT_DATA_SIZE];

        // Keeping the last byte different than the other bytes to ensure it is
        // independent from the other bytes in the array.
        left[left.len() - 1] = 0b1010_1010u8;
        right[right.len() - 1] = 0b1010_1010u8;
        expected[expected.len() - 1] = 0b1010_1010u8;
        assert_eq!(
            ReportData::from(left) & ReportData::from(right),
            ReportData::from(expected)
        );
    }

    #[test]
    fn bitwise_and_report_data_by_ref() {
        let left = [1u8; SGX_REPORT_DATA_SIZE];
        let right = [0u8; SGX_REPORT_DATA_SIZE];
        let expected = [0u8; SGX_REPORT_DATA_SIZE];

        assert_eq!(
            &ReportData::from(left) & &ReportData::from(right),
            ReportData::from(expected)
        );
    }
}
