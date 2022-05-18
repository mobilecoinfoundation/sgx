// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI type bindings for tservice, (trusted service) of the Intel
//! SGX SDK
extern crate bindgen;
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

fn main() {
    let bindings = bindgen::Builder::default()
        .header_contents(
            "tservice.h",
            "#include <sgx_tseal.h>\n#include <sgx_dh.h>\n#include <sgx_utils.h>",
        )
        .clang_arg(&format!("-I{}/include", sgx_library_path()))
        // TODO need to move this out to a common SGX crate
        .newtype_enum("_status_t")
        .blocklist_function("*")
        // `_sgx_dh_msg3_body_t` is a packed struct that bindgen can't derive
        // Copy for, which will result in E0133.
        .no_debug("_sgx_dh_msg3_body_t")
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
