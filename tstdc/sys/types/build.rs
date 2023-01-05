// Copyright (c) 2022-2023 The MobileCoin Foundation
//! Builds the FFI type bindings for tstdc (trusted standard C) of the
//! Intel SGX SDK

use bindgen::callbacks::ParseCallbacks;

#[derive(Debug)]
struct TstdcParseCallbacks;

impl ParseCallbacks for TstdcParseCallbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        mc_sgx_core_build::normalize_item_name(name).map(|normie| match normie.as_str() {
            "sgx_thread_cond_attr_t" | "sgx_thread_rwlock_attr_t" | "sgx_thread_mutex_attr_t" => {
                normie.replace("_attr_", "attr_")
            }
            _ => normie,
        })
    }
}

fn main() {
    let out_path = mc_sgx_core_build::build_output_dir();

    mc_sgx_core_build::sgx_builder()
        // override the default ParseCallbacks impl provided by mc_sgx_core_build
        .parse_callbacks(Box::new(TstdcParseCallbacks))
        .header("wrapper.h")
        .allowlist_recursively(false)
        .allowlist_type("sgx_thread_t")
        .allowlist_type("_sgx_thread_queue_t")
        .allowlist_type("_sgx_thread_cond_t")
        .allowlist_type("_sgx_thread_mutex_t")
        .allowlist_type("_sgx_thread_cond_attr_t")
        .allowlist_type("_sgx_thread_rwlock_t")
        .allowlist_type("_sgx_thread_rwlock_attr_t")
        .allowlist_type("_sgx_thread_mutex_attr_t")
        .allowlist_type("sgx_spinlock_t")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
