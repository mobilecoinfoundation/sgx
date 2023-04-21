// Copyright (c) 2022-2023 The MobileCoin Foundation
//! SGX core SVN (Security Version Numbers)

use crate::{impl_newtype_for_bytestruct, impl_newtype_no_display};
use constant_time_derive::ConstantTimeEq;
use core::fmt::{Display, Formatter};
use mc_sgx_core_sys_types::{sgx_config_svn_t, sgx_cpu_svn_t, sgx_isv_svn_t, SGX_CPUSVN_SIZE};
use subtle::{Choice, ConstantTimeGreater, ConstantTimeLess};

/// Config security version number (SVN)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default, ConstantTimeEq)]
pub struct ConfigSvn(sgx_config_svn_t);

impl_newtype_no_display! {
    ConfigSvn, sgx_config_svn_t;
}

impl Display for ConfigSvn {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ConstantTimeGreater for ConfigSvn {
    fn ct_gt(&self, other: &Self) -> Choice {
        self.0.ct_gt(&other.0)
    }
}

impl ConstantTimeLess for ConfigSvn {}

/// Independent software vendor (ISV) security version number (SVN)
#[repr(transparent)]
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Default, ConstantTimeEq)]
pub struct IsvSvn(sgx_isv_svn_t);

impl_newtype_no_display! {
    IsvSvn, sgx_isv_svn_t;
}

impl Display for IsvSvn {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ConstantTimeGreater for IsvSvn {
    fn ct_gt(&self, other: &Self) -> Choice {
        self.0.ct_gt(&other.0)
    }
}

impl ConstantTimeLess for IsvSvn {}

/// CPU security version number (SVN)
#[repr(transparent)]
#[derive(Default, Debug, Clone, Hash, PartialEq, Eq, ConstantTimeEq)]
pub struct CpuSvn(sgx_cpu_svn_t);

impl_newtype_for_bytestruct! {
    CpuSvn, sgx_cpu_svn_t, SGX_CPUSVN_SIZE, svn;
}

impl ConstantTimeGreater for CpuSvn {
    fn ct_gt(&self, other: &Self) -> Choice {
        let svn_self = u128::from_le_bytes(self.0.svn);
        let svn_other = u128::from_le_bytes(other.0.svn);
        svn_self.ct_gt(&svn_other)
    }
}

impl ConstantTimeLess for CpuSvn {}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use std::format;
    use subtle::ConstantTimeEq;

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

    #[test]
    fn ct_eq_config_svn() {
        let first = ConfigSvn(1);
        let second = ConfigSvn(1);

        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_gt_config_svn() {
        let first = ConfigSvn(2);
        let second = ConfigSvn(1);

        assert!(bool::from(first.ct_gt(&second)));
    }

    #[test]
    fn ct_lt_config_svn() {
        let first = ConfigSvn(1);
        let second = ConfigSvn(4);

        assert!(bool::from(first.ct_lt(&second)));
    }

    #[test]
    fn ct_eq_isv_svn() {
        let first_info = IsvSvn(1);
        let second_info = IsvSvn(1);

        let choice_result = first_info.ct_eq(&second_info);
        let result: bool = From::from(choice_result);

        assert!(result);
    }

    #[test]
    fn ct_gt_isv_svn() {
        let first = IsvSvn(3);
        let second = IsvSvn(1);

        assert!(bool::from(first.ct_gt(&second)));
    }

    #[test]
    fn ct_lt_isv_svn() {
        let first = IsvSvn(1);
        let second = IsvSvn(4);

        assert!(bool::from(first.ct_lt(&second)));
    }

    #[test]
    fn ct_eq_cpu_svn() {
        let first = CpuSvn(sgx_cpu_svn_t { svn: [1u8; 16] });
        let second = CpuSvn(sgx_cpu_svn_t { svn: [1u8; 16] });

        assert!(bool::from(first.ct_eq(&second)));
    }

    #[test]
    fn ct_gt_cpu_svn() {
        let first = CpuSvn(sgx_cpu_svn_t { svn: [2u8; 16] });
        let second = CpuSvn(sgx_cpu_svn_t { svn: [1u8; 16] });

        assert!(bool::from(first.ct_gt(&second)));
    }

    #[test]
    fn ct_lt_cpu_svn() {
        let first = CpuSvn(sgx_cpu_svn_t { svn: [1u8; 16] });
        let second = CpuSvn(sgx_cpu_svn_t { svn: [4u8; 16] });

        assert!(bool::from(first.ct_lt(&second)));
    }

    #[test]
    fn ct_not_eq_config_svn() {
        let first = ConfigSvn(1);
        let second = ConfigSvn(4);

        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_gt_config_svn() {
        let first = ConfigSvn(2);
        let second = ConfigSvn(2);

        assert!(bool::from(!first.ct_gt(&second)));
    }

    #[test]
    fn ct_not_lt_config_svn() {
        let first = ConfigSvn(8);
        let second = ConfigSvn(4);

        assert!(bool::from(!first.ct_lt(&second)));
    }

    #[test]
    fn ct_not_eq_isv_svn() {
        let first = IsvSvn(1);
        let second = IsvSvn(5);

        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_gt_isv_svn() {
        let first = IsvSvn(3);
        let second = IsvSvn(3);

        assert!(bool::from(!first.ct_gt(&second)));
    }

    #[test]
    fn ct_not_lt_isv_svn() {
        let first = IsvSvn(4);
        let second = IsvSvn(4);

        assert!(bool::from(!first.ct_lt(&second)));
    }

    #[test]
    fn ct_not_eq_cpu_svn() {
        let first = CpuSvn(sgx_cpu_svn_t { svn: [7u8; 16] });
        let second = CpuSvn(sgx_cpu_svn_t { svn: [3u8; 16] });

        assert!(bool::from(!first.ct_eq(&second)));
    }

    #[test]
    fn ct_not_gt_cpu_svn() {
        let first = CpuSvn(sgx_cpu_svn_t { svn: [6u8; 16] });
        let second = CpuSvn(sgx_cpu_svn_t { svn: [9u8; 16] });

        assert!(bool::from(!first.ct_gt(&second)));
    }

    #[test]
    fn ct_not_lt_cpu_svn() {
        let first = CpuSvn(sgx_cpu_svn_t { svn: [8u8; 16] });
        let second = CpuSvn(sgx_cpu_svn_t { svn: [4u8; 16] });

        assert!(bool::from(!first.ct_lt(&second)));
    }
}
