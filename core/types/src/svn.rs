// Copyright (c) 2022 The MobileCoin Foundation
//! SGX core SVN (Security Version Numbers)

use crate::{impl_newtype_for_bytestruct, new_type_accessors_impls};
use mc_sgx_core_sys_types::{
    sgx_config_id_t, sgx_config_svn_t, sgx_cpu_svn_t, sgx_isv_svn_t, SGX_CONFIGID_SIZE,
    SGX_CPUSVN_SIZE,
};

#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct ConfigSvn(sgx_config_svn_t);

new_type_accessors_impls! {
    ConfigSvn, sgx_config_svn_t;
}

impl ConfigSvn {
    pub fn new(svn: u16) -> Self {
        ConfigSvn(svn)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct IsvSvn(sgx_isv_svn_t);

new_type_accessors_impls! {
    IsvSvn, sgx_isv_svn_t;
}

impl IsvSvn {
    pub fn new(svn: u16) -> Self {
        IsvSvn(svn)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct CpuSvn(sgx_cpu_svn_t);

impl_newtype_for_bytestruct! {
    CpuSvn, sgx_cpu_svn_t, SGX_CPUSVN_SIZE, svn;
}

/// Config ID
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct ConfigId(sgx_config_id_t);

new_type_accessors_impls! {
    ConfigId, sgx_config_id_t;
}

impl ConfigId {
    pub const SIZE: usize = SGX_CONFIGID_SIZE;
    pub fn new(id: [u8; Self::SIZE]) -> Self {
        Self(id)
    }
}

impl Default for ConfigId {
    fn default() -> Self {
        Self::new([0; Self::SIZE])
    }
}
