// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI type bindings for the types used by libsgx_capable.{so,a} in SGX SDK types

use bindgen::{callbacks::ParseCallbacks, Builder};
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

#[derive(Debug)]
struct Callbacks;

fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

fn main() {
    let bindings = Builder::default()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}/include", sgx_library_path()))
        .blocklist_function("*")
        .newtype_enum("sgx_device_status_t")
        .ctypes_prefix("core::ffi")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
