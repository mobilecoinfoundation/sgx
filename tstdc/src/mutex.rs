// Copyright (c) 2023-2024 The MobileCoin Foundation

//! Mutex functionality for use inside of an SGX enclave

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
    LockNotOwned,
}

type Result<T> = core::result::Result<T, Error>;

/// Rust wrapper for an SGX SDK mutex used inside of an enclave.
///
/// A [`Mutex`] does *not* wrap up data directly. It is a primitive which can be
/// used to create a higher level Mutex analogous to
/// [`std::sync::Mutex`](https://doc.rust-lang.org/std/sync/struct.Mutex.html).
/// It handles locking, unlocking and freeing of the underlying SGX SDK mutex
///
/// NB: per the documentation of
/// [`sgx_thread_mutex_lock()`](https://download.01.org/intel-sgx/sgx-linux/2.18/docs/Intel_SGX_Developer_Reference_Linux_2.18_Open_Source.pdf#%5B%7B%22num%22%3A303%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C94.5%2C341.25%2C0%5D)
/// a mutex should not be locked across root ECALLs.
///
/// Threads that run inside the enclave are created within the (untrusted)
/// application.
///
/// Each concurrent root ECALL that starts from the (untrusted) application will
/// use a separate thread in the SGX enclave. [`Mutex`]es can be used to protect
/// shared global data that needs to be accessed by multiple concurrent root
/// ECALLs.
// SAFETY: The `sgx_thread_mutex_*` C functions utilize a spinlock to prevent
//  concurrent access to the underlying `sgx_thread_mutex_t`
#[derive(Debug, Default)]
pub struct Mutex(UnsafeCell<sgx_thread_mutex_t>);

unsafe impl Send for Mutex {}
unsafe impl Sync for Mutex {}

impl Mutex {
    /// Create a new non recursive mutex
    pub const fn new() -> Self {
        Self(UnsafeCell::new(SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER))
    }

    /// Lock this [`Mutex`] instance
    ///
    /// Blocks the current thread waiting for the mutex lock or an [`Error`].
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

    /// Try to lock this [`Mutex`] instance
    ///
    /// Returns `true` if the `Mutex` was locked, `false` if another thread has
    /// the `Mutex` locked.
    ///
    /// # Errors
    /// - [`Error::Invalid`] if self is invalid or trying to lock self when
    /// already holding a lock on self.
    pub fn try_lock(&self) -> Result<bool> {
        let result = unsafe { sgx_thread_mutex_trylock(self.0.get()) };
        match result {
            0 => Ok(true),
            libc::EBUSY => Ok(false),
            _ => Err(Error::Invalid),
        }
    }

    /// Unlock this [`Mutex`] instance
    ///
    /// Returns immediately with [`Ok`] or an [`Error`].
    ///
    /// # Errors
    /// - [`Error::LockNotOwned`] if another thread has the lock.
    /// - [`Error::Invalid`] if the `Mutex` is invalid or trying to unlock the
    ///   `Mutex` when it's not locked.
    pub fn unlock(&self) -> Result<()> {
        let result = unsafe { sgx_thread_mutex_unlock(self.0.get()) };
        match result {
            0 => Ok(()),
            libc::EPERM => Err(Error::LockNotOwned),
            _ => Err(Error::Invalid),
        }
    }

    /// Get at the underlying SGX mutex primitive.
    ///
    /// Callers are responsible for ensuring the returned value is *not* used
    /// after the original [`Mutex`]'s lifetime.
    pub(crate) unsafe fn raw(&self) -> *mut sgx_thread_mutex_t {
        self.0.get()
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
