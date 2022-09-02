// Copyright (c) 2022 The MobileCoin Foundation
//! SGX TargetInfo

use crate::{
    config_id::ConfigId, new_type_accessors_impls, Attributes, ConfigSvn, Measurement,
    MiscellaneousSelect,
};
use mc_sgx_core_sys_types::sgx_target_info_t;

/// The target info
#[repr(transparent)]
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct TargetInfo(sgx_target_info_t);

impl TargetInfo {
    /// The MRENCLAVE measurement
    pub fn mr_enclave(&self) -> Measurement {
        Measurement::MrEnclave(self.0.mr_enclave.into())
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

new_type_accessors_impls! {
    TargetInfo, sgx_target_info_t;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::MrEnclave;
    use mc_sgx_core_sys_types::{
        SGX_CONFIGID_SIZE, SGX_HASH_SIZE, SGX_TARGET_INFO_RESERVED1_BYTES,
        SGX_TARGET_INFO_RESERVED2_BYTES, SGX_TARGET_INFO_RESERVED3_BYTES,
    };

    #[test]
    fn default_target_info() {
        let info = TargetInfo::default();
        assert_eq!(
            info.mr_enclave(),
            Measurement::MrEnclave(MrEnclave::default())
        );
        assert_eq!(info.attributes(), Attributes::default());
        assert_eq!(info.config_svn(), ConfigSvn::default());
        assert_eq!(info.miscellaneous_select(), MiscellaneousSelect::default());
        assert_eq!(info.config_id(), ConfigId::default());
    }

    #[test]
    fn from_target_info_t() {
        let info = sgx_target_info_t {
            mr_enclave: MrEnclave::from([1u8; MrEnclave::SIZE]).into(),
            attributes: Attributes::default().set_flags(2).set_transform(3).into(),
            reserved1: [4u8; SGX_TARGET_INFO_RESERVED1_BYTES],
            config_svn: 5,
            misc_select: 6,
            reserved2: [7u8; SGX_TARGET_INFO_RESERVED2_BYTES],
            config_id: [8u8; SGX_CONFIGID_SIZE],
            reserved3: [9u8; SGX_TARGET_INFO_RESERVED3_BYTES],
        };

        let info: TargetInfo = info.into();

        assert_eq!(
            info.mr_enclave(),
            Measurement::MrEnclave(MrEnclave::from([1u8; SGX_HASH_SIZE]))
        );
        assert_eq!(
            info.attributes(),
            Attributes::default().set_flags(2).set_transform(3)
        );
        assert_eq!(info.config_svn(), ConfigSvn::new(5));
        assert_eq!(info.miscellaneous_select(), MiscellaneousSelect::new(6));
        assert_eq!(info.config_id(), ConfigId::from([8; SGX_CONFIGID_SIZE]));
    }
}
