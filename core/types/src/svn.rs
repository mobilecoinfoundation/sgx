// Copyright (c) 2022-2023 The MobileCoin Foundation
//! SGX core SVN (Security Version Numbers)

use crate::{impl_newtype, impl_newtype_for_bytestruct_no_display};
use core::fmt::{Display, Formatter};
use mc_sgx_core_sys_types::{sgx_config_svn_t, sgx_cpu_svn_t, sgx_isv_svn_t, SGX_CPUSVN_SIZE};

/// Config security version number (SVN)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
pub struct ConfigSvn(sgx_config_svn_t);

impl_newtype! {
    ConfigSvn, sgx_config_svn_t;
}

/// Independent software vendor (ISV) security version number (SVN)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default)]
pub struct IsvSvn(sgx_isv_svn_t);

impl_newtype! {
    IsvSvn, sgx_isv_svn_t;
}

/// CPU security version number (SVN)
#[repr(transparent)]
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct CpuSvn(sgx_cpu_svn_t);

impl Display for CpuSvn {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "CpuSvn: {:X}", self)
    }
}

impl_newtype_for_bytestruct_no_display! {
    CpuSvn, sgx_cpu_svn_t, SGX_CPUSVN_SIZE, svn;
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use std::format;

    #[test]
    fn cpu_svn_display() {
        let cpu_svn = CpuSvn::from([1u8; CpuSvn::SIZE]);

        let display_string = format!("{}", cpu_svn);
        let expected_string = "CpuSvn: 0101_0101_0101_0101_0101_0101_0101_0101";

        assert_eq!(display_string, expected_string);
    }
}
