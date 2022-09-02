// Copyright (c) 2022 The MobileCoin Foundation
//! SGX Report

use crate::{
    config_id::ConfigId, impl_newtype_for_bytestruct, key_request::KeyId, new_type_accessors_impls,
    Attributes, ConfigSvn, CpuSvn, IsvSvn, Measurement, MiscellaneousSelect, MrEnclave, MrSigner,
};
use core::mem;
use mc_sgx_core_sys_types::{
    sgx_isvext_prod_id_t, sgx_isvfamily_id_t, sgx_mac_t, sgx_prod_id_t, sgx_report_body_t,
    sgx_report_data_t, sgx_report_t, SGX_CONFIGID_SIZE, SGX_CPUSVN_SIZE, SGX_HASH_SIZE,
    SGX_ISVEXT_PROD_ID_SIZE, SGX_ISV_FAMILY_ID_SIZE, SGX_REPORT_DATA_SIZE,
};

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
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
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
    pub fn mr_enclave(&self) -> Measurement {
        Measurement::MrEnclave(self.0.mr_enclave.into())
    }

    /// The MRSIGNER measurement
    pub fn mr_signer(&self) -> Measurement {
        Measurement::MrSigner(self.0.mr_signer.into())
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

impl From<[u8; mem::size_of::<sgx_report_body_t>()]> for ReportBody {
    fn from(bytes: [u8; mem::size_of::<sgx_report_body_t>()]) -> Self {
        // A note about the `expect()` calls.  This size is specified in the
        // signature and there are unit tests ensuring the extraction from a
        // byte array.  The values should not fail to extract due to size
        // issues.
        let mut body = Self::default();

        let cpu_svn: [u8; SGX_CPUSVN_SIZE] =
            bytes[..16].try_into().expect("Failed to extract `cpu_svn`");
        body.0.cpu_svn = CpuSvn::from(cpu_svn).into();
        body.0.misc_select = u32::from_le_bytes(
            bytes[16..20]
                .try_into()
                .expect("Failed to extract `misc_select`"),
        );
        let extended_prod_id: [u8; SGX_ISVEXT_PROD_ID_SIZE] = bytes[32..48]
            .try_into()
            .expect("Failed to extract `isv_ext_prod_id`");
        body.0.isv_ext_prod_id = ExtendedProductId::from(extended_prod_id).into();
        body.0.attributes.flags = u64::from_le_bytes(
            bytes[48..56]
                .try_into()
                .expect("Failed to extract `attributes.flags`"),
        );
        body.0.attributes.xfrm = u64::from_le_bytes(
            bytes[56..64]
                .try_into()
                .expect("Failed to extract `attributes.xfrm`"),
        );
        let mr_enclave: [u8; SGX_HASH_SIZE] = bytes[64..96]
            .try_into()
            .expect("Failed to extract `mr_enclave`");
        body.0.mr_enclave = MrEnclave::from(mr_enclave).into();
        let mr_signer: [u8; SGX_HASH_SIZE] = bytes[128..160]
            .try_into()
            .expect("Failed to extract `mr_signer`");
        body.0.mr_signer = MrSigner::from(mr_signer).into();
        let config_id: [u8; SGX_CONFIGID_SIZE] = bytes[192..256]
            .try_into()
            .expect("Failed to extract `config_id`");
        body.0.config_id = ConfigId::from(config_id).into();
        body.0.isv_prod_id = u16::from_le_bytes(
            bytes[256..258]
                .try_into()
                .expect("Failed to extract `isv_prod_id`"),
        );
        body.0.isv_svn = u16::from_le_bytes(
            bytes[258..260]
                .try_into()
                .expect("Failed to extract `isv_svn`"),
        );
        body.0.config_svn = u16::from_le_bytes(
            bytes[260..262]
                .try_into()
                .expect("Failed to extract `config_svn`"),
        );
        let isv_family_id: [u8; SGX_ISV_FAMILY_ID_SIZE] = bytes[304..320]
            .try_into()
            .expect("Failed to extract `isv_family_id`");
        body.0.isv_family_id = FamilyId::from(isv_family_id).into();
        let report_data: [u8; SGX_REPORT_DATA_SIZE] = bytes[320..384]
            .try_into()
            .expect("Failed to extract `report_data`");
        body.0.report_data = ReportData::from(report_data).into();
        body
    }
}

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
    use core::slice;
    use mc_sgx_core_sys_types::{
        SGX_CONFIGID_SIZE, SGX_HASH_SIZE, SGX_ISVEXT_PROD_ID_SIZE, SGX_ISV_FAMILY_ID_SIZE,
        SGX_KEYID_SIZE, SGX_MAC_SIZE, SGX_REPORT_BODY_RESERVED1_BYTES,
        SGX_REPORT_BODY_RESERVED2_BYTES, SGX_REPORT_BODY_RESERVED3_BYTES,
        SGX_REPORT_BODY_RESERVED4_BYTES,
    };

    fn report_body_1() -> sgx_report_body_t {
        sgx_report_body_t {
            cpu_svn: CpuSvn::from([1u8; CpuSvn::SIZE]).into(),
            misc_select: 2,
            reserved1: [3u8; SGX_REPORT_BODY_RESERVED1_BYTES],
            isv_ext_prod_id: [4u8; SGX_ISVEXT_PROD_ID_SIZE],
            attributes: Attributes::default().set_flags(5).set_transform(6).into(),
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
            attributes: Attributes::default().set_flags(52).set_transform(62).into(),
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

    fn report_body_to_bytes(body: sgx_report_body_t) -> [u8; mem::size_of::<sgx_report_body_t>()] {
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
        assert_eq!(
            body.mr_enclave(),
            Measurement::MrEnclave(MrEnclave::default())
        );
        assert_eq!(body.mr_signer(), Measurement::MrSigner(MrSigner::default()));
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
        let body = ReportBody::from(bytes);
        assert_eq!(body.cpu_svn(), CpuSvn::from([1u8; CpuSvn::SIZE]));
        assert_eq!(body.miscellaneous_select(), MiscellaneousSelect::new(2));
        assert_eq!(
            body.isv_extended_product_id(),
            ExtendedProductId([4u8; SGX_ISVEXT_PROD_ID_SIZE])
        );
        assert_eq!(
            body.attributes(),
            Attributes::default().set_flags(5).set_transform(6)
        );
        assert_eq!(
            body.mr_enclave(),
            Measurement::MrEnclave(MrEnclave::from([7u8; SGX_HASH_SIZE]))
        );
        assert_eq!(
            body.mr_signer(),
            Measurement::MrSigner(MrSigner::from([9u8; SGX_HASH_SIZE]))
        );
        assert_eq!(body.config_id(), ConfigId::from([11u8; SGX_CONFIGID_SIZE]));
        assert_eq!(body.isv_product_id(), IsvProductId(12));
        assert_eq!(body.isv_svn(), IsvSvn::new(13));
        assert_eq!(body.config_svn(), ConfigSvn::new(14));
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
    fn report_body_2_from_bytes() {
        let bytes = report_body_to_bytes(report_body_2());
        let body = ReportBody::from(bytes);
        assert_eq!(body.cpu_svn(), CpuSvn::from([12u8; CpuSvn::SIZE]));
        assert_eq!(body.miscellaneous_select(), MiscellaneousSelect::new(22));
        assert_eq!(
            body.isv_extended_product_id(),
            ExtendedProductId([42u8; SGX_ISVEXT_PROD_ID_SIZE])
        );
        assert_eq!(
            body.attributes(),
            Attributes::default().set_flags(52).set_transform(62)
        );
        assert_eq!(
            body.mr_enclave(),
            Measurement::MrEnclave(MrEnclave::from([72u8; SGX_HASH_SIZE]))
        );
        assert_eq!(
            body.mr_signer(),
            Measurement::MrSigner(MrSigner::from([92u8; SGX_HASH_SIZE]))
        );
        assert_eq!(body.config_id(), ConfigId::from([112u8; SGX_CONFIGID_SIZE]));
        assert_eq!(body.isv_product_id(), IsvProductId(122));
        assert_eq!(body.isv_svn(), IsvSvn::new(132));
        assert_eq!(body.config_svn(), ConfigSvn::new(142));
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
}
