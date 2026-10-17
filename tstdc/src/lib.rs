// Copyright (c) 2023-2025 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![deny(missing_docs, missing_debug_implementations)]
#![no_std]

mod condvar;
mod mutex;
mod rwlock;
pub use condvar::{Condvar, Error as CondvarError};
pub use mutex::{Error as MutexError, Mutex};
pub use rwlock::{Error as RwLockError, RwLock};
