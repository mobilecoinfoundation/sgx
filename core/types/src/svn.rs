// Copyright (c) 2022 The MobileCoin Foundation
//! SGX core SVN (Security Version Numbers)

use crate::new_type_accessors_impls;
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

new_type_accessors_impls! {
    CpuSvn, sgx_cpu_svn_t;
}

impl CpuSvn {
    pub const SVN_SIZE: usize = SGX_CPUSVN_SIZE;
    pub fn new(svn: &[u8; Self::SVN_SIZE]) -> Self {
        let mut cpu_svn = Self::default();
        cpu_svn.0.svn.copy_from_slice(svn);
        cpu_svn
    }
}

impl Default for CpuSvn {
    fn default() -> Self {
        CpuSvn(sgx_cpu_svn_t {
            svn: [0; Self::SVN_SIZE],
        })
    }
}
