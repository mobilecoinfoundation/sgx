// Copyright (c) 2022-2023 The MobileCoin Foundation
//! SGX core SVN (Security Version Numbers)

use crate::{impl_newtype, impl_newtype_for_bytestruct, impl_newtype_no_display};
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

impl_newtype_no_display! {
    IsvSvn, sgx_isv_svn_t;
}

/// CPU security version number (SVN)
#[repr(transparent)]
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct CpuSvn(sgx_cpu_svn_t);

impl_newtype_for_bytestruct! {
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
        let expected_string = "0x0101_0101_0101_0101_0101_0101_0101_0101";

        assert_eq!(display_string, expected_string);
    }

    #[test]
    fn isv_svn_display() {
        let sgx_isv_svn_t = 3459;
        let isv_svn = IsvSvn::from(sgx_isv_svn_t);

        let display_string = format!("{}", isv_svn);
        let expected_string = "0x0D83";

        assert_eq!(display_string, expected_string);
    }
}
