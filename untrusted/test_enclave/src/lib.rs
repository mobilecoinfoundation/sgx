// Copyright (c) 2022 The MobileCoin Foundation
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

/// The test enclave as bytes.
pub static ENCLAVE: &'static [u8] = include_bytes!(concat!(env!("OUT_DIR"), "/libenclave.signed.so"));

use mc_sgx_urts_sys_types::{sgx_enclave_id_t, sgx_report_t, sgx_status_t, sgx_target_info_t};
use std::mem::MaybeUninit;
use std::ptr;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// Returns the report for the enclave pertaining to `eid`
///
/// # Errors
///
/// When there is an error getting the enclave report this will return the
/// result of the call.
///
/// This will be the non never be `sgx_status_t::SGX_SUCCESS`.
///
/// # Arguments
/// - `eid` the enclave to get the report for
/// - `target_info` The target info to use.  When this is `None`
///     it is intended for the implementation to pass `null` as the
///     `target_info` to
///     [`sgx_create_report()`](https://download.01.org/intel-sgx/sgx-linux/2.8/docs/Intel_SGX_Developer_Reference_Linux_2.8_Open_Source.pdf#%5B%7B%22num%22%3A281%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C94.5%2C179.25%2C0%5D).
pub fn enclave_report(eid: sgx_enclave_id_t, target_info: Option<&sgx_target_info_t>) -> Result<sgx_report_t, sgx_status_t> {
    let report = MaybeUninit::zeroed();
    let mut report = unsafe { report.assume_init() };
    let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
    let info = match target_info {
        Some(info) => info,
        None => ptr::null(),
    };
    let result = unsafe { ecall_create_report(eid, &mut retval, info, &mut report) };
    match result {
        sgx_status_t::SGX_SUCCESS => match retval {
            sgx_status_t::SGX_SUCCESS => Ok(report),
            x => Err(x),
        },
        x => Err(x),
    }
}
