// Copyright (c) 2022 The MobileCoin Foundation
//! SGX Config ID

use crate::new_type_accessors_impls;
use mc_sgx_core_sys_types::{sgx_config_id_t, SGX_CONFIGID_SIZE};

/// Config ID
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct ConfigId(sgx_config_id_t);

new_type_accessors_impls! {
    ConfigId, sgx_config_id_t;
}

impl Default for ConfigId {
    fn default() -> Self {
        Self::from([0; SGX_CONFIGID_SIZE])
    }
}
