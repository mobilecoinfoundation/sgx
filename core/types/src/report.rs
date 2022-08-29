// Copyright (c) 2022 The MobileCoin Foundation
//! SGX Report

use crate::{
    config_id::ConfigId, impl_newtype_for_bytestruct, key_request::KeyId, new_type_accessors_impls,
    Attributes, ConfigSvn, CpuSvn, IsvSvn, Measurement, MiscellaneousSelect, MrEnclave, MrSigner,
};
use mc_sgx_core_sys_types::{
    sgx_isvext_prod_id_t, sgx_isvfamily_id_t, sgx_mac_t, sgx_prod_id_t, sgx_report_body_t,
    sgx_report_data_t, sgx_report_t, SGX_ISVEXT_PROD_ID_SIZE, SGX_REPORT_BODY_RESERVED1_BYTES,
    SGX_REPORT_BODY_RESERVED2_BYTES, SGX_REPORT_BODY_RESERVED3_BYTES,
    SGX_REPORT_BODY_RESERVED4_BYTES, SGX_REPORT_DATA_SIZE,
};

/// MAC
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct Mac(sgx_mac_t);

new_type_accessors_impls! {
    Mac, sgx_mac_t;
}

/// Report Data
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct ExtendedProductId(sgx_isvext_prod_id_t);

new_type_accessors_impls! {
    ExtendedProductId, sgx_isvext_prod_id_t;
}

impl Default for ExtendedProductId {
    fn default() -> Self {
        Self([0; SGX_ISVEXT_PROD_ID_SIZE])
    }
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
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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

// Implementing default to make it easier to pass an `sgx_report_body_t` to the
// sgx functions.
// ```
// let mut report: sgx_report_body_t = Report::default().into()
// let return_value = unsafe{ sgx_some_call(&report as *mut _) }
// ```
impl Default for ReportBody {
    fn default() -> Self {
        Self(sgx_report_body_t {
            cpu_svn: CpuSvn::default().into(),
            misc_select: MiscellaneousSelect::default().into(),
            reserved1: [0u8; SGX_REPORT_BODY_RESERVED1_BYTES],
            isv_ext_prod_id: ExtendedProductId::default().into(),
            attributes: Attributes::default().into(),
            mr_enclave: MrEnclave::default().into(),
            reserved2: [0u8; SGX_REPORT_BODY_RESERVED2_BYTES],
            mr_signer: MrSigner::default().into(),
            reserved3: [0u8; SGX_REPORT_BODY_RESERVED3_BYTES],
            config_id: ConfigId::default().into(),
            isv_prod_id: IsvProductId::default().into(),
            isv_svn: IsvSvn::default().into(),
            config_svn: ConfigSvn::default().into(),
            reserved4: [0u8; SGX_REPORT_BODY_RESERVED4_BYTES],
            isv_family_id: FamilyId::default().into(),
            report_data: ReportData::default().into(),
        })
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
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

impl Default for Report {
    fn default() -> Self {
        Self(sgx_report_t {
            body: ReportBody::default().into(),
            key_id: KeyId::default().into(),
            mac: Mac::default().into(),
        })
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use crate::key_request::KeyId;
    use mc_sgx_core_sys_types::{
        SGX_CONFIGID_SIZE, SGX_HASH_SIZE, SGX_ISV_FAMILY_ID_SIZE, SGX_KEYID_SIZE, SGX_MAC_SIZE,
    };

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
    fn from_sgx_report_body_t() {
        let sgx_body = sgx_report_body_t {
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
        };

        let body: ReportBody = sgx_body.into();

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
