// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI function bindings for tstdc (trusted standard C) of the
//! Intel SGX SDK

use bindgen::Builder;
use cargo_emit::{rustc_link_lib, rustc_link_search};

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    rustc_link_lib!("sgx_tstdc");
    rustc_link_search!(&format!("{}/lib64", sgx_library_path));

    let out_path = mc_sgx_core_build::build_output_path();
    Builder::default()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .allowlist_recursively(false)
        .blocklist_type("*")
        .allowlist_function("sgx_thread.*")
        .allowlist_function("sgx_alloc.*")
        .allowlist_function("sgx_spin.*")
        .allowlist_function("sgx_cpuid.*")
        .allowlist_function("sgx_.*rsrv.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .ctypes_prefix("core::ffi")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
