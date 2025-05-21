// Copyright (c) 2022-2025 The MobileCoin Foundation
//! SGX Config ID

use crate::impl_newtype_no_display;
use core::fmt::{Display, Formatter};
use mc_sgx_core_sys_types::{sgx_config_id_t, SGX_CONFIGID_SIZE};

/// Config ID
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct ConfigId(sgx_config_id_t);

impl_newtype_no_display! {
    ConfigId, sgx_config_id_t;
}

impl Display for ConfigId {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        mc_sgx_util::fmt_hex(&self.0, f)
    }
}

// Pure array type larger than 32 so must implement default at the newtype level
impl Default for ConfigId {
    fn default() -> Self {
        Self::from([0; SGX_CONFIGID_SIZE])
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::format;

    #[test]
    fn display_config_id() {
        let inner = [34u8; 64];
        let config_id = ConfigId::from(inner);

        let display_string = format!("{config_id}");
        let expected = "0x2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222_2222";

        assert_eq!(display_string, expected);
    }
}
