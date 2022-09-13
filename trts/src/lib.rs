// Copyright (c) 2022 MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations)]

use core::{ffi::c_void, mem};
use mc_sgx_trts_sys::{sgx_is_outside_enclave, sgx_is_within_enclave};

/// Behavior for determining where memory values are at.
pub trait EnclaveMemory<T> {
    /// Is the item fully within the enclave's memory space?
    ///
    /// # Arguments
    /// - `item` - The item to see if it's fully inside of the enclave's memory
    ///   space
    fn is_within_enclave(item: &T) -> bool;

    /// Is the item fully outside of the enclave's memory space?
    ///
    /// # Arguments
    /// - `item` - The item to see if it's fully outside of the enclave's memory
    ///   space
    fn is_outside_enclave(item: &T) -> bool;
}

impl<T: Sized> EnclaveMemory<T> for T {
    fn is_within_enclave(item: &T) -> bool {
        let start = item as *const _ as *const c_void;
        let size = mem::size_of::<T>();
        matches!(unsafe { sgx_is_within_enclave(start, size) }, 1)
    }

    fn is_outside_enclave(item: &T) -> bool {
        let start = item as *const _ as *const c_void;
        let size = mem::size_of::<T>();
        matches!(unsafe { sgx_is_outside_enclave(start, size) }, 1)
    }
}
