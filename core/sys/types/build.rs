// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the common SGX SDK types

use bindgen::{callbacks::ParseCallbacks, Builder};
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        match name {
            "_status_t" => Some("sgx_status_t".to_owned()),
            _ => None,
        }
    }
}

fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

fn main() {
    let bindings = Builder::default()
        .header_contents("core_types.h", "#include <sgx_error.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path()))
        .newtype_enum("_status_t")
        .blocklist_function("*")
        .allowlist_type("_status_t")
        .parse_callbacks(Box::new(Callbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
