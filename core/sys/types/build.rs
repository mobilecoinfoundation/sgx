// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the common SGX SDK types

use bindgen::{callbacks::ParseCallbacks, Builder};

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

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let bindings = Builder::default()
        .header_contents(
            "core_types.h",
            "#include <sgx_error.h>\n#include <sgx_report.h>",
        )
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .newtype_enum("_status_t")
        .blocklist_function("*")
        .allowlist_type("_status_t")
        .allowlist_type("sgx_target_info_t")
        .parse_callbacks(Box::new(Callbacks))
        .ctypes_prefix("core::ffi")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = mc_sgx_core_build::build_output_path();
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
