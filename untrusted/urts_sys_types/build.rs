// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI bindings for the untrusted side of the Intel SGX SDK
extern crate bindgen;
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

fn main() {
    let bindings = bindgen::Builder::default()
        .header_contents("urts_types.h", "#include <sgx_urts.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path()))
        .newtype_enum("_status_t")
        .blocklist_function("*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Suppressing warnings from tests, see
        // https://github.com/rust-lang/rust-bindgen/issues/1651
        .layout_tests(false)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
