// Copyright (c) 2023 The MobileCoin Foundation

//! Reader/writer lock functionality for use inside of an SGX enclave

use core::cell::UnsafeCell;
use mc_sgx_tstdc_sys::{
    sgx_thread_rwlock_destroy, sgx_thread_rwlock_rdlock, sgx_thread_rwlock_rdunlock,
    sgx_thread_rwlock_tryrdlock, sgx_thread_rwlock_trywrlock, sgx_thread_rwlock_wrlock,
    sgx_thread_rwlock_wrunlock,
};
use mc_sgx_tstdc_sys_types::{sgx_thread_rwlock_t, SGX_THREAD_LOCK_INITIALIZER};

/// Errors when interacting with [`RwLock`]s
#[derive(Copy, Clone, Debug, displaydoc::Display, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub enum Error {
    /// Invalid operation on the [`RwLock`]
    Invalid,
    /// [`RwLock`] is currently locked by another thread
    Busy,
    /// [`RwLock`] is already locked for write by this thread
    WriteLocked,
    /// Ran out of memory
    NoMemory,
}

type Result<T> = core::result::Result<T, Error>;

/// Rust wrapper for an SGX SDK rwlock used inside of an enclave.
///
/// An [`RwLock`] does *not* wrap up data directly. It is a primitive which can
/// be used to create a higher level RwLock analogous to
/// [`std::sync::RwLock`](https://doc.rust-lang.org/std/sync/struct.RwLock.html).
/// It handles locking, unlocking and freeing of the underlying SGX SDK rwlock.
///
/// NB: per the documentation of
/// [`sgx_thread_rwlock_rdlock()`](https://download.01.org/intel-sgx/sgx-linux/2.18/docs/Intel_SGX_Developer_Reference_Linux_2.18_Open_Source.pdf#%5B%7B%22num%22%3A308%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C94.5%2C319.5%2C0%5D)
/// an rwlock should not be locked across root ECALLs.
///
/// Read locks are implemented using a reference count. This means that clients
/// are responsible for managing which threads hold the read locks and ensuring
/// threads only unlock if they are currently holding a reader lock. Write locks
/// do track which thread owns them.
///
/// Threads that run inside the enclave are created within the (untrusted)
/// application.
///
/// Each concurrent root ECALL that starts from the (untrusted) application will
/// use a separate thread in the SGX enclave. [`RwLock`]s can be used to protect
/// shared global data that needs to be accessed by multiple concurrent root
/// ECALLs.
// SAFETY: The `sgx_thread_rwlock_*` C functions utilize a spinlock to prevent
//  concurrent access to the underlying `sgx_thread_rwlock_t`
#[derive(Debug, Default)]
pub struct RwLock(UnsafeCell<sgx_thread_rwlock_t>);

unsafe impl Send for RwLock {}
unsafe impl Sync for RwLock {}

impl RwLock {
    /// Create a new [`RwLock`]
    pub const fn new() -> RwLock {
        Self(UnsafeCell::new(SGX_THREAD_LOCK_INITIALIZER))
    }

    /// Acquire a reader lock on the [`RwLock`] instance.
    ///
    /// Ensures that no other threads hold a writer lock on the [`RwLock`]
    /// instance. If no other threads hold a writer lock, the reader lock is
    /// acquired and the function returns successfully. If another thread is
    /// currently holding a writer lock, will block until the writer lock is
    /// released.
    ///
    /// NB: This acquires **a** reader lock on the [`RwLock`] instance, it does
    ///     not keep track of which threads have reader locks.
    ///
    /// # Errors
    /// - [`Error::WriteLocked`] if the current thread has a write lock on the
    ///   [`RwLock`] instance.
    /// - [`Error::Invalid`] if the [`RwLock`] instance is invalid.
    pub fn read(&self) -> Result<()> {
        let result = unsafe { sgx_thread_rwlock_rdlock(self.0.get()) };
        match result {
            0 => Ok(()),
            libc::EDEADLK => Err(Error::WriteLocked),
            _ => Err(Error::Invalid),
        }
    }

    /// Try to acquire a reader lock on the [`RwLock`] instance.
    ///
    /// If no other threads hold a writer lock on the [`RwLock`] instance, the
    /// reader lock is acquired. If another thread is currently holding a writer
    /// lock, returns [`Error::Busy`].
    ///
    /// NB: This acquires **a** reader lock on the [`RwLock`] instance, it does
    ///     not keep track of which threads have reader locks.
    ///
    /// # Errors
    /// - [`Error::Busy`] if another thread has a writer lock on the [`RwLock`]
    ///   instance.
    /// - [`Error::WriteLocked`] if the current thread has a write lock on the
    ///   [`RwLock`] instance.
    /// - [`Error::Invalid`] if the [`RwLock`] instance is invalid.
    pub fn try_read(&self) -> Result<()> {
        let result = unsafe { sgx_thread_rwlock_tryrdlock(self.0.get()) };
        match result {
            0 => Ok(()),
            libc::EBUSY => Err(Error::Busy),
            libc::EDEADLK => Err(Error::WriteLocked),
            _ => Err(Error::Invalid),
        }
    }

    /// Acquire a writer lock on the [`RwLock`] instance.
    ///
    /// Ensures that no other threads hold either a reader or a writer lock on
    /// the [`RwLock`] instance. If no other threads hold a either a reader or a
    /// writer lock, the writer lock is acquired. If another thread currently
    /// holds either lock, will block until either the writer lock or all the
    /// reader locks are released.
    ///
    /// # Errors
    /// - [`Error::WriteLocked`] if the current thread already has the write
    ///   lock on the [`RwLock`] instance.
    /// - [`Error::Invalid`] if the [`RwLock`] instance is invalid.
    pub fn write(&self) -> Result<()> {
        let result = unsafe { sgx_thread_rwlock_wrlock(self.0.get()) };
        match result {
            0 => Ok(()),
            libc::EDEADLK => Err(Error::WriteLocked),
            _ => Err(Error::Invalid),
        }
    }

    /// Try to acquire a writer lock on the [`RwLock`] instance.
    ///
    /// If no other threads hold either a reader lock or a writer lock on the
    /// [`RwLock`] instance, the writer lock is acquired. If another thread
    /// holds a lock, the function returns [`Error::Busy`].
    ///
    /// # Errors
    /// - [`Error::Busy`] if another thread has either a reader or a writer lock
    ///   on the [`RwLock`] instance.
    /// - [`Error::WriteLocked`] if the current thread already has the write
    ///   lock on the [`RwLock`] instance.
    /// - [`Error::Invalid`] if the [`RwLock`] instance is invalid.
    pub fn try_write(&self) -> Result<()> {
        let result = unsafe { sgx_thread_rwlock_trywrlock(self.0.get()) };
        match result {
            0 => Ok(()),
            libc::EBUSY => Err(Error::Busy),
            libc::EDEADLK => Err(Error::WriteLocked),
            _ => Err(Error::Invalid),
        }
    }

    /// Release a reader lock on the [`RwLock`] instance.
    ///
    /// NB: This release **a** reader lock on the [`RwLock`] instance, it does
    ///     not validate that the current thread created the reader lock.
    ///
    /// # Errors
    /// [`Error::Invalid`] if the [`RwLock`] instance is invalid or there are
    /// no read locks on the [`RwLock`] instance.
    pub fn read_unlock(&self) -> Result<()> {
        let result = unsafe { sgx_thread_rwlock_rdunlock(self.0.get()) };
        match result {
            0 => Ok(()),
            _ => Err(Error::Invalid),
        }
    }

    /// Release a write lock on the [`RwLock`] instance.
    ///
    /// # Errors
    /// - [`Error::NoMemory`] if out of memory occurs when trying to wake up
    ///   threads waiting for reader locks.
    /// - [`Error::Invalid`] if the [`RwLock`] instance is invalid or the
    ///   current thread doesn't hold the write lock.
    pub fn write_unlock(&self) -> Result<()> {
        let result = unsafe { sgx_thread_rwlock_wrunlock(self.0.get()) };
        match result {
            0 => Ok(()),
            libc::ENOMEM => Err(Error::NoMemory),
            _ => Err(Error::Invalid),
        }
    }
}

impl Drop for RwLock {
    fn drop(&mut self) {
        let result = unsafe { sgx_thread_rwlock_destroy(self.0.get()) };
        // There is no good way to recover from failing to destroy the rwlock so
        // we leak it in release
        debug_assert_eq!(result, 0);
    }
}
