// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI bindings for the untrusted side of the Intel SGX SDK
use bindgen::{callbacks::ParseCallbacks, Builder};
use std::{env, path::PathBuf};

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        match name {
            "_attributes_t" => Some("sgx_attributes_t".to_owned()),
            "_sgx_misc_attribute_t" => Some("sgx_misc_attribute_t".to_owned()),
            _ => None,
        }
    }
}

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let bindings = Builder::default()
        .header_contents("urts_types.h", "#include <sgx_urts.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .blocklist_function("*")
        .allowlist_type("sgx_enclave_id_t")
        .allowlist_type("sgx_launch_token_t")
        .allowlist_type("sgx_misc_attribute_t")
        .parse_callbacks(Box::new(Callbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
