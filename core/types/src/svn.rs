// Copyright (c) 2022 The MobileCoin Foundation
//! SGX core SVN (Security Version Numbers)

use crate::{impl_newtype_for_bytestruct, new_type_accessors_impls};
use mc_sgx_core_sys_types::{sgx_config_svn_t, sgx_cpu_svn_t, sgx_isv_svn_t, SGX_CPUSVN_SIZE};

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
