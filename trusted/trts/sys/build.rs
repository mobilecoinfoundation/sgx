// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI function bindings for trts (trusted runtime system) of the
//! Intel SGX SDK
extern crate bindgen;
use cargo_emit::{rustc_link_lib, rustc_link_search};
use std::{env, path::PathBuf};
use mc_sgx_core_build;

#[cfg(feature = "hw")]
const SGX_SUFFIX: &str = "";
#[cfg(not(feature = "hw"))]
const SGX_SUFFIX: &str = "_sim";

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    rustc_link_lib!(&format!("sgx_trts{}", SGX_SUFFIX));
    rustc_link_search!(&format!("{}/lib64", &sgx_library_path));

    let bindings = bindgen::Builder::default()
        .header_contents("trts.h", "#include <sgx_trts.h>")
        .clang_arg(&format!("-I{}/include", &sgx_library_path))
        .blocklist_type("*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .ctypes_prefix("core::ffi")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").expect("Missing env.OUT_DIR"));
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
