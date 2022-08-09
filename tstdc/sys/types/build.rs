// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for tstdc (trusted standard C) of the
//! Intel SGX SDK

use bindgen::{callbacks::ParseCallbacks, Builder, EnumVariation};

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        if name.contains("_attr") {
            Some(name[1..].replace("_attr", "attr"))
        } else if name.starts_with("_sgx") {
            Some(name[1..].to_owned())
        } else {
            None
        }
    }
}

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();

    let out_path = mc_sgx_core_build::build_output_path();

    Builder::default()
        .header("wrapper.h")
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_ord(true)
        .derive_partialeq(true)
        .derive_partialord(true)
        .default_enum_style(EnumVariation::Consts)
        .prepend_enum_name(false)
        .clang_arg(&format!("-I{}/include", sgx_library_path))
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
        .parse_callbacks(Box::new(Callbacks))
        .use_core()
        .ctypes_prefix("core::ffi")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
