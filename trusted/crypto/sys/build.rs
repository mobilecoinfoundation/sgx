// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI function bindings for trts (trusted runtime system) of the
//! Intel SGX SDK
extern crate bindgen;
use cargo_emit::{rustc_link_lib, rustc_link_search};
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

fn main() {
    rustc_link_lib!("sgx_tcrypto");
    rustc_link_search!(&format!("{}/lib64", sgx_library_path()));

    let bindings = bindgen::Builder::default()
        .header_contents("crypto.h", "#include <sgx_tcrypto.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path()))
        .blocklist_type("*")
        // Limit the functions to what is currently supported.  There are ~48
        // total functions in tcrypto which will be brought in over a series
        // of commits
        .allowlist_function("sgx_sha256_.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Suppressing warnings from tests, see
        // https://github.com/rust-lang/rust-bindgen/issues/1651
        .layout_tests(false)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").expect("Missing env.OUT_DIR"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
