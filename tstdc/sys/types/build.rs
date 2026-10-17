// Copyright (c) 2022-2025 The MobileCoin Foundation
//! Builds the FFI type bindings for tstdc (trusted standard C) of the
//! Intel SGX SDK

use mc_sgx_core_build::SgxParseCallbacks;

const TSTDC_TYPES: &[&str] = &[
    "sgx_thread_t",
    "_sgx_thread_queue_t",
    "_sgx_thread_cond_t",
    "_sgx_thread_mutex_t",
    "_sgx_thread_cond_attr_t",
    "_sgx_thread_rwlock_t",
    "_sgx_thread_rwlock_attr_t",
    "_sgx_thread_mutex_attr_t",
    "sgx_spinlock_t",
];

const TSTDC_CONSTS: &[&str] = &[
    "SGX_THREAD_MUTEX_NONRECURSIVE",
    "SGX_THREAD_MUTEX_RECURSIVE",
];

fn main() {
    let callback = SgxParseCallbacks::default();

    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .parse_callbacks(Box::new(callback))
        .blocklist_function("*");

    for t in TSTDC_TYPES {
        builder = builder.allowlist_type(t);
    }

    for c in TSTDC_CONSTS.iter() {
        builder = builder.allowlist_var(c)
    }

    let out_path = mc_sgx_core_build::build_output_dir();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
