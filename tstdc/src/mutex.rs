// Copyright (c) 2023 The MobileCoin Foundation

//! Mutex functionality for an SGX enclave

use core::cell::UnsafeCell;
use mc_sgx_tstdc_sys::{
    sgx_thread_mutex_destroy, sgx_thread_mutex_lock, sgx_thread_mutex_trylock,
    sgx_thread_mutex_unlock,
};
use mc_sgx_tstdc_sys_types::{sgx_thread_mutex_t, SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER};

/// Errors when interacting with [`Mutex`]es
#[derive(Copy, Clone, Debug, displaydoc::Display, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Error {
    /// Invalid operation on the mutex
    Invalid,
    /// Mutex is currently locked by another thread
    Busy,
}

type Result<T> = core::result::Result<T, Error>;

/// A mutex inside of an SGX enclave
///
/// NB: per the documentation of
/// [`sgx_thread_mutex_lock()`](https://download.01.org/intel-sgx/sgx-linux/2.18/docs/Intel_SGX_Developer_Reference_Linux_2.18_Open_Source.pdf#%5B%7B%22num%22%3A303%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C94.5%2C341.25%2C0%5D)
/// a mutex should not be locked across root ECALLs.
#[derive(Debug, Default)]
pub struct Mutex(UnsafeCell<sgx_thread_mutex_t>);

// SAFETY: The `sgx_thread_mutex_*` C functions utilize a spinlock to prevent
//  concurrent access to the underlying `sgx_thread_mutex_t`
unsafe impl Send for Mutex {}
unsafe impl Sync for Mutex {}

impl Mutex {
    /// Create a new non recursive mutex
    pub const fn new() -> Self {
        Self(UnsafeCell::new(SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER))
    }

    /// Lock self
    ///
    /// Blocks the current thread waiting for the mutex lock or an error.
    ///
    /// # Errors
    /// [`Error::Invalid`] will be returned if self is invalid or trying to lock
    /// self when already holding a lock on self.
    pub fn lock(&self) -> Result<()> {
        let result = unsafe { sgx_thread_mutex_lock(self.0.get()) };
        match result {
            0 => Ok(()),
            _ => Err(Error::Invalid),
        }
    }

    /// Try to lock self
    ///
    /// Returns immediately with the mutex or an error
    ///
    /// # Errors
    /// - [`Error::Busy`] if another thread has the lock, or higher precedence
    ///   in obtaining the lock.
    /// - [`Error::Invalid`] if self is invalid or trying to lock self when
    ///   already holding a lock on self.
    pub fn try_lock(&self) -> Result<()> {
        let result = unsafe { sgx_thread_mutex_trylock(self.0.get()) };
        match result {
            0 => Ok(()),
            libc::EBUSY => Err(Error::Busy),
            _ => Err(Error::Invalid),
        }
    }

    /// Unlock self
    ///
    /// Returns immediately with the mutex or an error
    ///
    /// # Errors
    /// - [`Error::Busy`] if another thread has the lock.
    /// - [`Error::Invalid`] if self is invalid or trying to unlock self when
    ///   self is not locked.
    pub fn unlock(&self) -> Result<()> {
        let result = unsafe { sgx_thread_mutex_unlock(self.0.get()) };
        match result {
            0 => Ok(()),
            libc::EPERM => Err(Error::Busy),
            _ => Err(Error::Invalid),
        }
    }
}

impl Drop for Mutex {
    fn drop(&mut self) {
        let result = unsafe { sgx_thread_mutex_destroy(self.0.get()) };
        // There is no good way to recover from failing to destroy the mutex so
        // we leak it in release
        debug_assert_eq!(result, 0);
    }
}
