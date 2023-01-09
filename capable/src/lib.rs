// Copyright (c) 2022-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use mc_sgx_capable_sys_types::sgx_device_status_t;
use mc_sgx_capable_types::{Error, Result};
use mc_sgx_util::ResultInto;

/// Tests if the current system is capable of running SGX.
///
/// This function requires running the untrusted userspace application as an
/// administrator.
pub fn is_capable() -> Result<bool> {
    let mut value = 0;

    unsafe { mc_sgx_capable_sys::sgx_is_capable(&mut value as *mut _) }
        .into_result()
        .map_err(Error::from)
        .map(|_| value == 1)
}

/// Attempts to see if SGX is enabled.
///
/// This function requires running the untrusted userspace application as an
/// administrator.
///
/// Returns `Ok(())` when SGX is enable, or an
/// [`Error`](mc_sgx_capable_types::Error) indicating what would need to happen
/// to turn it on.
pub fn is_enabled() -> Result<()> {
    let mut device_status = sgx_device_status_t::SGX_DISABLED;

    unsafe { mc_sgx_capable_sys::sgx_cap_get_status(&mut device_status as *mut _) }
        .into_result()
        .map_err(Error::from)
        .and_then(|_| device_status.into_result())
}

/// Attempt to enable SGX programmatically.
///
/// This function requires running the untrusted userspace application as an
/// administrator.
///
/// Returns `Ok(())` if SGX is now enabled, or an
/// [`Error`](mc_sgx_capable_types::Error) indicating what would need to happen
/// to turn it on.
pub fn enable() -> Result<()> {
    let mut device_status = sgx_device_status_t::SGX_DISABLED;

    unsafe { mc_sgx_capable_sys::sgx_cap_enable_device(&mut device_status as *mut _) }
        .into_result()
        .map_err(Error::from)
        .and_then(|_| device_status.into_result())
}
