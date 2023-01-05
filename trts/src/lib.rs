// Copyright (c) 2022-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations)]

use core::ffi::c_void;
use mc_sgx_trts_sys::{sgx_is_outside_enclave, sgx_is_within_enclave};

/// Behavior for determining where memory values are at.
pub trait EnclaveMemory<T> {
    /// Is the item fully within the enclave's memory space?
    fn is_within_enclave(&self) -> bool;

    /// Is the item fully outside of the enclave's memory space?
    fn is_outside_enclave(&self) -> bool;
}

impl<T: AsRef<[u8]>> EnclaveMemory<T> for T {
    fn is_within_enclave(&self) -> bool {
        let start = self.as_ref().as_ptr() as *const c_void;
        let size = self.as_ref().len();
        let result = unsafe { sgx_is_within_enclave(start, size) };
        result == 1
    }

    fn is_outside_enclave(&self) -> bool {
        let start = self.as_ref().as_ptr() as *const c_void;
        let size = self.as_ref().len();
        let result = unsafe { sgx_is_outside_enclave(start, size) };
        result == 1
    }
}
