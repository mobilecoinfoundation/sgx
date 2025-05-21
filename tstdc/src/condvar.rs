// Copyright (c) 2023-2025 The MobileCoin Foundation

//! Condition variable functionality for use inside of an SGX enclave

use crate::Mutex;
use core::cell::UnsafeCell;
use mc_sgx_tstdc_sys::{
    sgx_thread_cond_broadcast, sgx_thread_cond_destroy, sgx_thread_cond_signal,
    sgx_thread_cond_wait,
};
use mc_sgx_tstdc_sys_types::{sgx_thread_cond_t, SGX_THREAD_COND_INITIALIZER};

/// Errors when interacting with [`Condvar`]s
#[derive(Copy, Clone, Debug, displaydoc::Display, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Error {
    /// Invalid operation on the condition variable
    Invalid,
    /// The paired mutex is locked by another thread
    MutexLock,
    /// Ran out of memory
    OutOfMemory,
}

type Result<T> = core::result::Result<T, Error>;

/// Rust wrapper for an SGX SDK condition variable used inside of an enclave.
///
/// A condition variable indicates an event and has no value. More precisely,
/// one cannot store a value into nor retrieve a value from a condition
/// variable. If a thread must wait for an event to occur, that thread waits on
/// the corresponding condition variable. If another thread causes an event to
/// occur, that thread signals the corresponding condition variable.
///
/// [`Condvar`]s are paired with a [`Mutex`]. The [`Mutex`] is locked prior to
/// waiting on the [`Condvar`]. Internally the [`Mutex`] will be freed while the
/// thread waits on the [`Condvar`]. When the thread returns from
/// [`Condvar::wait()`] the [`Mutex`] will be locked by the thread.
// SAFETY: The `sgx_thread_cond_*` C functions utilize a spinlock to prevent
//  concurrent access to the underlying `sgx_thread_cond_t`
#[derive(Debug, Default)]
pub struct Condvar(UnsafeCell<sgx_thread_cond_t>);

unsafe impl Send for Condvar {}
unsafe impl Sync for Condvar {}

impl Condvar {
    /// Create a new condition variable
    pub const fn new() -> Self {
        Self(UnsafeCell::new(SGX_THREAD_COND_INITIALIZER))
    }

    /// Blocks the current thread until this condition variable receives a
    /// notification.
    ///
    /// # Arguments:
    /// * `mutex` - The [`Mutex`] used to guard the condition variable. This
    ///   should be locked by the current thread.
    ///
    /// # Errors
    /// - [`Error::MutexLock`] if another thread has the [`Mutex`] lock.
    /// - [`Error::Invalid`] if self is invalid
    ///
    /// # Examples
    ///
    /// ```
    /// use mc_sgx_tstdc::{Mutex, Condvar};
    ///
    /// let pair = (Mutex::new(), Condvar::new());
    ///
    /// // Wait for the thread to start up.
    /// let (mutex, cvar) = &*pair;
    /// // mutex must be locked prior to waiting
    /// mutex.lock().unwrap();
    /// // wait with the mutex. The mutex will be unlocked and relocked inside
    /// // of `wait()` as needed while `cvar` is waiting.
    /// cvar.wait(mutex).unwrap();
    /// // cvar done waiting, mutex is again locked by this thread.
    /// mutex.unlock();
    ///
    /// // do stuff
    ///
    /// ```
    pub fn wait(&self, mutex: &Mutex) -> Result<()> {
        let result = unsafe { sgx_thread_cond_wait(self.0.get(), mutex.raw()) };
        match result {
            0 => Ok(()),
            libc::EPERM => Err(Error::MutexLock),
            _ => Err(Error::Invalid),
        }
    }

    /// Notifies the next thread (if any) waiting on the condition variable
    ///
    /// If there are no threads waiting ([`Condvar::wait()`]) on the condition
    /// variable nothing happens.
    ///
    /// # Errors
    /// [`Error::Invalid`] if self is invalid
    pub fn notify_one(&self) -> Result<()> {
        let result = unsafe { sgx_thread_cond_signal(self.0.get()) };
        match result {
            0 => Ok(()),
            _ => Err(Error::Invalid),
        }
    }

    /// Notifies *all* threads (if any) waiting on the condition variable
    ///
    /// If there are no threads waiting ([`Condvar::wait()`]) on the condition
    /// variable nothing happens.
    ///
    /// # Errors
    /// - [`Error::OutOfMemory`] if out of memory occurs when notifying all
    ///   waiting threads
    /// - [`Error::Invalid`] if self is invalid
    pub fn notify_all(&self) -> Result<()> {
        let result = unsafe { sgx_thread_cond_broadcast(self.0.get()) };
        match result {
            0 => Ok(()),
            libc::ENOMEM => Err(Error::OutOfMemory),
            _ => Err(Error::Invalid),
        }
    }
}

impl Drop for Condvar {
    fn drop(&mut self) {
        let result = unsafe { sgx_thread_cond_destroy(self.0.get()) };
        // There is no good way to recover from failing to destroy the condition
        // variable so we leak it in release
        debug_assert_eq!(result, 0);
    }
}
