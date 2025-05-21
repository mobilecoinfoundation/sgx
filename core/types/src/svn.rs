// Copyright (c) 2022-2025 The MobileCoin Foundation
//! SGX core SVN (Security Version Numbers)

use crate::{impl_display_for_bytestruct, impl_newtype_for_bytestruct, impl_newtype_no_display};
use core::fmt::{Display, Formatter};
use mc_sgx_core_sys_types::{sgx_config_svn_t, sgx_cpu_svn_t, sgx_isv_svn_t, SGX_CPUSVN_SIZE};

/// Config security version number (SVN)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct ConfigSvn(sgx_config_svn_t);

impl_newtype_no_display! {
    ConfigSvn, sgx_config_svn_t;
}

impl Display for ConfigSvn {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Independent software vendor (ISV) security version number (SVN)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default, PartialOrd, Ord)]
pub struct IsvSvn(sgx_isv_svn_t);

impl_newtype_no_display! {
    IsvSvn, sgx_isv_svn_t;
}

impl Display for IsvSvn {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// CPU security version number (SVN)
#[repr(transparent)]
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
pub struct CpuSvn(sgx_cpu_svn_t);

impl_newtype_for_bytestruct! {
    CpuSvn, sgx_cpu_svn_t, SGX_CPUSVN_SIZE, svn;
}
impl_display_for_bytestruct!(CpuSvn);

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use std::format;

    #[test]
    fn cpu_svn_display() {
        let cpu_svn = CpuSvn::from([1u8; CpuSvn::SIZE]);

        let display_string = format!("{cpu_svn}");
        let expected_string = "0x0101_0101_0101_0101_0101_0101_0101_0101";

        assert_eq!(display_string, expected_string);
    }

    #[test]
    fn isv_svn_display() {
        let inner = 3459;
        let isv_svn = IsvSvn::from(inner);

        let display_string = format!("{isv_svn}");
        let expected_string = format!("{inner}");

        assert_eq!(display_string, expected_string);
    }

    #[test]
    fn config_svn_display() {
        let inner = 3298;
        let config_svn = ConfigSvn::from(inner);

        let display_string = format!("{config_svn}");
        let expected_string = format!("{inner}");

        assert_eq!(display_string, expected_string);
    }
}
