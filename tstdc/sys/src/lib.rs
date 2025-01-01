// Copyright (c) 2022-2025 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use mc_sgx_core_sys_types::sgx_status_t;
use mc_sgx_tstdc_sys_types::{
    sgx_spinlock_t, sgx_thread_cond_t, sgx_thread_condattr_t, sgx_thread_mutex_t,
    sgx_thread_mutexattr_t, sgx_thread_rwlock_t, sgx_thread_rwlockattr_t, sgx_thread_t,
};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
