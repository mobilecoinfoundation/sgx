// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI function bindings for tservice, (trusted service) of the
//! Intel Intel SGX SDK
extern crate bindgen;
use cargo_emit::{rustc_link_lib, rustc_link_search};
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

#[cfg(feature = "hw")]
const SGX_SUFFIX: &str = "";
#[cfg(not(feature = "hw"))]
const SGX_SUFFIX: &str = "_sim";

fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

fn main() {
    rustc_link_lib!(&format!("sgx_tservice{}", SGX_SUFFIX));
    rustc_link_search!(&format!("{}/lib64", sgx_library_path()));

    let bindings = bindgen::Builder::default()
        .header_contents(
            "tservice.h",
            "#include <sgx_tseal.h>\n#include <sgx_dh.h>\n#include <sgx_utils.h>",
        )
        .clang_arg(&format!("-I{}/include", sgx_library_path()))
        .blocklist_type("*")
        // Only bring in the functions currently supported with rust interfaces
        // Other functions will get added in subsequent commits
        .allowlist_function("sgx_calc_sealed_data_size")
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
