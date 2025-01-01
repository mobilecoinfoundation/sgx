// Copyright (c) 2022-2025 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// `SGX_THREAD_T_NULL`, `SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER`,
// `SGX_THREAD_RECURSIVE_MUTEX_INITIALIZER`, `SGX_THREAD_LOCK_INITIALIZER`,
// and `SGX_THREAD_COND_INITIALIZER` are defined using macros in
// `sgx_thread.h` as such we need to manually redefine them in rust.

const SGX_THREAD_T_NULL: usize = 0;

// A constant implementation for creating a `sgx_thread_queue_t` to make
// constructing dependee constants easier
impl sgx_thread_queue_t {
    /// Create a new `sgx_thread_queue_t`
    pub const fn new() -> Self {
        Self {
            m_first: SGX_THREAD_T_NULL,
            m_last: SGX_THREAD_T_NULL,
        }
    }
}

impl Default for sgx_thread_queue_t {
    fn default() -> Self {
        Self::new()
    }
}

pub const SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER: sgx_thread_mutex_t = sgx_thread_mutex_t {
    m_refcount: 0,
    m_control: SGX_THREAD_MUTEX_NONRECURSIVE,
    m_lock: 0,
    m_owner: SGX_THREAD_T_NULL,
    m_queue: sgx_thread_queue_t::new(),
};

pub const SGX_THREAD_RECURSIVE_MUTEX_INITIALIZER: sgx_thread_mutex_t = sgx_thread_mutex_t {
    m_refcount: 0,
    m_control: SGX_THREAD_MUTEX_RECURSIVE,
    m_lock: 0,
    m_owner: SGX_THREAD_T_NULL,
    m_queue: sgx_thread_queue_t::new(),
};

/// Default `sgx_thread_mutex_t` to be used in place of
/// `SGX_THREAD_MUTEX_INITIALIZER`
impl Default for sgx_thread_mutex_t {
    fn default() -> Self {
        SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER
    }
}

pub const SGX_THREAD_LOCK_INITIALIZER: sgx_thread_rwlock_t = sgx_thread_rwlock_t {
    m_reader_count: 0,
    m_writers_waiting: 0,
    m_lock: 0,
    m_owner: SGX_THREAD_T_NULL,
    m_reader_queue: sgx_thread_queue_t::new(),
    m_writer_queue: sgx_thread_queue_t::new(),
};

impl Default for sgx_thread_rwlock_t {
    fn default() -> Self {
        SGX_THREAD_LOCK_INITIALIZER
    }
}

pub const SGX_THREAD_COND_INITIALIZER: sgx_thread_cond_t = sgx_thread_cond_t {
    m_lock: 0,
    m_queue: sgx_thread_queue_t::new(),
};

impl Default for sgx_thread_cond_t {
    fn default() -> Self {
        SGX_THREAD_COND_INITIALIZER
    }
}
