// Copyright (c) 2022-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]

use core::result::Result as CoreResult;
use mc_sgx_capable_sys_types::sgx_device_status_t;
use mc_sgx_core_types::Error as SgxError;
use mc_sgx_util::{ResultFrom, ResultInto};

/// Convenience type for handling SGX capable results
pub type Result<T> = CoreResult<T, Error>;

/// An enumeration of errors which could occur when attempting to enable SGX
/// through software.
#[derive(Copy, Clone, Debug, displaydoc::Display, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[non_exhaustive]
pub enum Error {
    /// An unknown error occurred
    Unknown,
    /// SGX has been enabled for the next reboot
    RebootRequired,
    /// SGX can be enabled using the Software Control Interface
    SciAvailable,
    /// SGX must be enabled in BIOS settings
    ManualEnable,
    /// Hyper-V must be disabled before SGX can be enabled
    HyperVEnabled,
    /// The running OS does not support enabling SGX through UEFI
    LegacyOs,
    /// This CPU does not support SGX
    UnsupportedCpu,
    /// SGX must be enabled in BIOS settings
    Disabled,
    /// Administrator privileges are required to read and set EFI variables
    Sgx(SgxError),
}

impl From<SgxError> for Error {
    fn from(err: SgxError) -> Self {
        Error::Sgx(err)
    }
}

/// Try to convert an
/// [`sgx_device_status_t`](mc_sgx_capable_sys_types::sgx_device_status_t) to an
/// [`Error`].
///
/// This is fallible because device_status_t also includes
/// [`SGX_ENABLED`](mc_sgx_capable_sys_types::sgx_device_status_t::SGX_ENABLED),
/// which is not an error.
///
/// As a result, we need to use this here, so the preferred way to actually do
/// FFI with this is best done via
/// [`ResultFrom`](mc_sgx_util::ResultFrom) or
/// [`ResultInto`](mc_sgx_util::ResultInto) implementation.
///
/// # Example
///
/// ```
/// use mc_sgx_capable_sys_types::sgx_device_status_t;
/// use mc_sgx_capable_types::{Error, Result};
/// use mc_sgx_util::ResultFrom;
///
/// fn foo() -> Result<bool> {
///     let device_status = sgx_device_status_t::SGX_DISABLED;
///
///     // Convert the status into a `Result<(), Err>`, change () to true
///     Error::result_from(device_status).map(|_| true)
/// }
/// ```
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

impl ResultFrom<sgx_device_status_t> for Error {}
impl ResultInto<Error> for sgx_device_status_t {}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_util::ResultInto;
    use yare::parameterized;

    #[parameterized(
        enabled = { sgx_device_status_t::SGX_ENABLED, Ok(()) },
        reboot_required = { sgx_device_status_t::SGX_DISABLED_REBOOT_REQUIRED, Err(Error::RebootRequired) },
        legacy_os = { sgx_device_status_t::SGX_DISABLED_LEGACY_OS, Err(Error::LegacyOs) },
        disabled = { sgx_device_status_t::SGX_DISABLED, Err(Error::Disabled) },
        sci_available = { sgx_device_status_t::SGX_DISABLED_SCI_AVAILABLE, Err(Error::SciAvailable) },
        manual_enable = { sgx_device_status_t::SGX_DISABLED_MANUAL_ENABLE, Err(Error::ManualEnable) },
        hyperv_enabled = { sgx_device_status_t::SGX_DISABLED_HYPERV_ENABLED, Err(Error::HyperVEnabled) },
        unsupported_cpu = { sgx_device_status_t::SGX_DISABLED_UNSUPPORTED_CPU, Err(Error::UnsupportedCpu) },
    )]
    fn device_status_into_result(actual: sgx_device_status_t, expected: CoreResult<(), Error>) {
        assert_eq!(actual.into_result(), expected);
    }
}
