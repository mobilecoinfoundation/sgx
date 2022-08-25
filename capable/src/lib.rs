// Copyright (c) 2022 MobileCoin Foundation

#![doc = include_str!("../README.md")]

use mc_sgx_capable_sys_types::sgx_device_status_t;
use mc_sgx_capable_types::{Error, Result};
use mc_sgx_core_sys_types::sgx_status_t;
use mc_sgx_core_types::Error as SgxError;

/// Tests if the current system is capable of running SGX.
///
/// This function requires running the untrusted userspace application as an
/// administrator.
pub fn is_capable() -> Result<bool> {
    let mut value = 0;
    let status = unsafe { mc_sgx_capable_sys::sgx_is_capable(&mut value as *mut _) };
    if status == sgx_status_t::SGX_SUCCESS {
        Ok(value == 1)
    } else {
        Err(Error::from(SgxError::from(status)))
    }
}

// FIXME: Make the whole process of going from a status to a result way more
//        monadic.
fn handle_retval(status: sgx_status_t, device_status: sgx_device_status_t) -> Result<()> {
    if status == sgx_status_t::SGX_SUCCESS {
        if let Ok(err) = Error::try_from(device_status) {
            Err(err)
        } else {
            Ok(())
        }
    } else {
        Err(SgxError::from(status).into())
    }
}

/// Attempts to see if SGX is enabled.
///
/// This function requires running the untrusted userspace application as an
/// administrator.
///
/// Returns `Ok(())` when SGX is enable, or an [Error] indicating what would
/// need to happen to turn it on.
pub fn is_enabled() -> Result<()> {
    let mut device_status = sgx_device_status_t::SGX_DISABLED;

    let status = unsafe { mc_sgx_capable_sys::sgx_cap_get_status(&mut device_status as *mut _) };
    handle_retval(status, device_status)
}

/// Attempt to enable SGX programmatically.
///
/// This function requires running the untrusted userspace application as an
/// administrator.
///
/// Returns `Ok(())` if SGX is now enabled, or an [Error] indicating what would
/// need to happen to turn it on.
pub fn enable() -> Result<()> {
    let mut device_status = sgx_device_status_t::SGX_DISABLED;

    let status = unsafe { mc_sgx_capable_sys::sgx_cap_enable_device(&mut device_status as *mut _) };
    handle_retval(status, device_status)
}

#[cfg(test)]
mod test {
    use super::*;
    use yare::parameterized;

    #[parameterized(
        ok = { sgx_status_t::SGX_SUCCESS, sgx_device_status_t::SGX_ENABLED, Ok(()) },
        status_fail = { sgx_status_t::SGX_ERROR_UNEXPECTED, sgx_device_status_t::SGX_ENABLED, Err(Error::Sgx(SgxError::Unexpected)) },
        no_priviledge = { sgx_status_t::SGX_ERROR_NO_PRIVILEGE, sgx_device_status_t::SGX_ENABLED, Err(Error::Sgx(SgxError::NoPrivilege)) },
        status_fail_has_precedence = { sgx_status_t::SGX_ERROR_NO_PRIVILEGE, sgx_device_status_t::SGX_DISABLED_MANUAL_ENABLE, Err(Error::Sgx(SgxError::NoPrivilege)) },
        device_status_fail = { sgx_status_t::SGX_SUCCESS, sgx_device_status_t::SGX_DISABLED_MANUAL_ENABLE, Err(Error::ManualEnable) },
    )]
    fn return_value_mapping(
        status: sgx_status_t,
        device_status: sgx_device_status_t,
        expected: Result<()>,
    ) {
        assert_eq!(handle_retval(status, device_status), expected);
    }
}
