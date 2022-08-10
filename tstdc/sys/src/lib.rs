// Copyright (c) 2022 The MobileCoin Foundation
//
#![no_std]
#![feature(c_size_t)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

pub use core::ffi::c_size_t as size_t;
use mc_sgx_core_sys_types::sgx_status_t;
use mc_sgx_tstdc_sys_types::{
    sgx_spinlock_t, sgx_thread_cond_t, sgx_thread_condattr_t, sgx_thread_mutex_t,
    sgx_thread_mutexattr_t, sgx_thread_rwlock_t, sgx_thread_rwlockattr_t, sgx_thread_t,
};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
