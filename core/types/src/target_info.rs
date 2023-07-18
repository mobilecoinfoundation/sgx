// Copyright (c) 2022-2023 The MobileCoin Foundation
//! SGX TargetInfo

use crate::{
    config_id::ConfigId, impl_newtype, Attributes, ConfigSvn, MiscellaneousSelect, MrEnclave,
};
use mc_sgx_core_sys_types::sgx_target_info_t;
use serde::{Deserialize, Serialize};

/// The target info
#[repr(transparent)]
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetInfo(sgx_target_info_t);

impl TargetInfo {
    /// The MRENCLAVE measurement
    pub fn mr_enclave(&self) -> MrEnclave {
        self.0.mr_enclave.into()
    }

    /// The attributes
    pub fn attributes(&self) -> Attributes {
        self.0.attributes.into()
    }

    /// The Config SVN
    pub fn config_svn(&self) -> ConfigSvn {
        self.0.config_svn.into()
    }

    /// Miscellaneous Select values
    pub fn miscellaneous_select(&self) -> MiscellaneousSelect {
        self.0.misc_select.into()
    }

    /// The Config ID
    pub fn config_id(&self) -> ConfigId {
        self.0.config_id.into()
    }
}

impl_newtype! {
    TargetInfo, sgx_target_info_t;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{AttributeFlags, ExtendedFeatureRequestMask};
    use mc_sgx_core_sys_types::{
        SGX_CONFIGID_SIZE, SGX_HASH_SIZE, SGX_TARGET_INFO_RESERVED1_BYTES,
        SGX_TARGET_INFO_RESERVED2_BYTES, SGX_TARGET_INFO_RESERVED3_BYTES,
    };

    #[test]
    fn default_target_info() {
        let info = TargetInfo::default();
        assert_eq!(info.mr_enclave(), MrEnclave::default());
        assert_eq!(info.attributes(), Attributes::default());
        assert_eq!(info.config_svn(), ConfigSvn::default());
        assert_eq!(info.miscellaneous_select(), MiscellaneousSelect::default());
        assert_eq!(info.config_id(), ConfigId::default());
    }

    #[test]
    fn from_target_info_t() {
        let info = sgx_target_info_t {
            mr_enclave: MrEnclave::from([1u8; MrEnclave::SIZE]).into(),
            attributes: Attributes::default()
                .set_flags(AttributeFlags::DEBUG)
                .set_extended_features_mask(ExtendedFeatureRequestMask::LEGACY)
                .into(),
            reserved1: [4u8; SGX_TARGET_INFO_RESERVED1_BYTES],
            config_svn: 5,
            misc_select: 6,
            reserved2: [7u8; SGX_TARGET_INFO_RESERVED2_BYTES],
            config_id: [8u8; SGX_CONFIGID_SIZE],
            reserved3: [9u8; SGX_TARGET_INFO_RESERVED3_BYTES],
        };

        let info: TargetInfo = info.into();

        assert_eq!(info.mr_enclave(), MrEnclave::from([1u8; SGX_HASH_SIZE]));
        assert_eq!(
            info.attributes(),
            Attributes::default()
                .set_flags(AttributeFlags::DEBUG)
                .set_extended_features_mask(ExtendedFeatureRequestMask::LEGACY)
        );
        assert_eq!(info.config_svn(), ConfigSvn::from(5));
        assert_eq!(info.miscellaneous_select(), MiscellaneousSelect::from(6));
        assert_eq!(info.config_id(), ConfigId::from([8; SGX_CONFIGID_SIZE]));
    }

    #[test]
    fn serialize_from_target_info_t() {
        let info = sgx_target_info_t {
            mr_enclave: MrEnclave::from([3u8; MrEnclave::SIZE]).into(),
            attributes: Attributes::default()
                .set_flags(AttributeFlags::MODE_64BIT)
                .set_extended_features_mask(ExtendedFeatureRequestMask::AVX)
                .into(),
            reserved1: [5u8; SGX_TARGET_INFO_RESERVED1_BYTES],
            config_svn: 6,
            misc_select: 7,
            reserved2: [8u8; SGX_TARGET_INFO_RESERVED2_BYTES],
            config_id: [9u8; SGX_CONFIGID_SIZE],
            reserved3: [10u8; SGX_TARGET_INFO_RESERVED3_BYTES],
        };

        // cbor is the format to go to/from an enclave in the main MobileCoin repo
        let bytes = serde_cbor::to_vec(&info).expect("failed to serialize");
        let target_info: TargetInfo =
            serde_cbor::from_slice(bytes.as_slice()).expect("failed to deserialize");

        assert_eq!(
            target_info.mr_enclave(),
            MrEnclave::from([3u8; SGX_HASH_SIZE])
        );
        assert_eq!(
            target_info.attributes(),
            Attributes::default()
                .set_flags(AttributeFlags::MODE_64BIT)
                .set_extended_features_mask(ExtendedFeatureRequestMask::AVX)
        );
        assert_eq!(target_info.config_svn(), ConfigSvn::from(6));
        assert_eq!(
            target_info.miscellaneous_select(),
            MiscellaneousSelect::from(7)
        );
        assert_eq!(
            target_info.config_id(),
            ConfigId::from([9; SGX_CONFIGID_SIZE])
        );
    }
}
