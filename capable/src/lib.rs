// Copyright (c) 2022 MobileCoin Foundation

#![doc = include_str!("../README.md")]

use mc_sgx_capable_sys_types::sgx_device_status_t;
use mc_sgx_capable_types::Result;
use mc_sgx_core_types::Error as SgxError;
use mc_sgx_util::{ResultFrom, ResultInto};

/// Tests if the current system is capable of running SGX.
///
/// This function requires running the untrusted userspace application as an
/// administrator.
pub fn is_capable() -> Result<bool> {
    let mut value = 0;

    SgxError::result_from(unsafe { mc_sgx_capable_sys::sgx_is_capable(&mut value as *mut _) })?;

    Ok(value == 1)
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

    SgxError::result_from(unsafe {
        mc_sgx_capable_sys::sgx_cap_get_status(&mut device_status as *mut _)
    })?;

    device_status.into_result()
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

    SgxError::result_from(unsafe {
        mc_sgx_capable_sys::sgx_cap_enable_device(&mut device_status as *mut _)
    })?;
    device_status.into_result()
}
