// Copyright (c) 2022 MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]

use core::result::Result as CoreResult;
use mc_sgx_capable_sys_types::sgx_device_status_t;
use mc_sgx_core_types::Error as SgxError;

/// Convenience type for handling SGX capable results
pub type Result<T> = CoreResult<T, Error>;

/// An enumeration of errors which could occur when attempting to enable SGX
/// through software.
#[derive(Copy, Clone, Debug, displaydoc::Display, Eq, Hash, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum Error {
    /// An unknown error occurred
    Unknown = -1,
    /// SGX has been enabled for the next reboot
    RebootRequired = sgx_device_status_t::SGX_DISABLED_REBOOT_REQUIRED.0 as isize,
    /// SGX can be enabled using the Software Control Interface
    SciAvailable = sgx_device_status_t::SGX_DISABLED_SCI_AVAILABLE.0 as isize,
    /// SGX must be enabled in BIOS settings
    ManualEnable = sgx_device_status_t::SGX_DISABLED_MANUAL_ENABLE.0 as isize,
    /// Hyper-V must be disabled before SGX can be enabled
    HyperVEnabled = sgx_device_status_t::SGX_DISABLED_HYPERV_ENABLED.0 as isize,
    /// The running OS does not support enabling SGX through UEFI
    LegacyOs = sgx_device_status_t::SGX_DISABLED_LEGACY_OS.0 as isize,
    /// This CPU does not support SGX
    UnsupportedCpu = sgx_device_status_t::SGX_DISABLED_UNSUPPORTED_CPU.0 as isize,
    /// SGX must be enabled in BIOS settings
    Disabled = sgx_device_status_t::SGX_DISABLED.0 as isize,
    /// Administrator privileges are required to read and set EFI variables
    NoPrivilege = -2,
}

impl From<SgxError> for Error {
    fn from(err: SgxError) -> Self {
        match err {
            SgxError::NoPrivilege => Error::NoPrivilege,
            _ => Error::Unknown,
        }
    }
}

/// Try to convert an sgx_device_status_t to an [Error].
///
/// This is fallible because device_status_t also includes
/// [`SGX_ENABLED`](mc_sgx_capable_sys_types::SGX_ENABLED), which is (obviously)
/// not an error.
///
/// As a result, we need to use this here, so the preferred way to actually do
/// FFI with this is going to look something like this:
///
/// ```
/// use mc_sgx_capable_sys_types::sgx_device_status_t;
/// use mc_sgx_capable_types::{Error, Result};
///
/// fn foo() -> Result<bool> {
///     let device_status = sgx_device_status_t::SGX_DISABLED;
///
///     // Actually do FFI to fill in device status here
///
///     if let Ok(err) = Error::try_from(device_status) {
///         return Err(err);
///     }
///
///     Ok(true)
/// }
/// ```
///
impl TryFrom<sgx_device_status_t> for Error {
    type Error = ();

    fn try_from(device_status: sgx_device_status_t) -> core::result::Result<Self, ()> {
        match device_status {
            sgx_device_status_t::SGX_ENABLED => Err(()),
            sgx_device_status_t::SGX_DISABLED_REBOOT_REQUIRED => Ok(Error::RebootRequired),
            sgx_device_status_t::SGX_DISABLED_SCI_AVAILABLE => Ok(Error::SciAvailable),
            sgx_device_status_t::SGX_DISABLED_MANUAL_ENABLE => Ok(Error::ManualEnable),
            sgx_device_status_t::SGX_DISABLED_HYPERV_ENABLED => Ok(Error::HyperVEnabled),
            sgx_device_status_t::SGX_DISABLED_LEGACY_OS => Ok(Error::LegacyOs),
            sgx_device_status_t::SGX_DISABLED_UNSUPPORTED_CPU => Ok(Error::UnsupportedCpu),
            sgx_device_status_t::SGX_DISABLED => Ok(Error::Disabled),
            _ => Ok(Error::Unknown),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use yare::parameterized;

    #[parameterized(
        enabled = { sgx_device_status_t::SGX_ENABLED, Err(()) },
        reboot_required = { sgx_device_status_t::SGX_DISABLED_REBOOT_REQUIRED, Ok(Error::RebootRequired) },
        legacy_os = { sgx_device_status_t::SGX_DISABLED_LEGACY_OS, Ok(Error::LegacyOs) },
        disabled = { sgx_device_status_t::SGX_DISABLED, Ok(Error::Disabled) },
        sci_available = { sgx_device_status_t::SGX_DISABLED_SCI_AVAILABLE, Ok(Error::SciAvailable) },
        manual_enable = { sgx_device_status_t::SGX_DISABLED_MANUAL_ENABLE, Ok(Error::ManualEnable) },
        hyperv_enabled = { sgx_device_status_t::SGX_DISABLED_HYPERV_ENABLED, Ok(Error::HyperVEnabled) },
        unsupported_cpu = { sgx_device_status_t::SGX_DISABLED_UNSUPPORTED_CPU, Ok(Error::UnsupportedCpu) },
    )]
    fn status_try_into_error(actual: sgx_device_status_t, expected: CoreResult<Error, ()>) {
        assert_eq!(Error::try_from(actual), expected);
    }
}
