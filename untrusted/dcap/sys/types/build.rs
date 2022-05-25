// Copyright (c) 2022 The MobileCoin Foundation

//! Build the FFI type bindings for DCAP (Data Center Attestation Primitives)
//! quote verification
extern crate bindgen;
use std::{env, path::PathBuf};

fn main() {
    let bindings = bindgen::Builder::default()
        .header_contents("dcap_qv.h", "#include <sgx_dcap_quoteverify.h>")
        .blocklist_function("*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Suppressing warnings from tests, see
        // https://github.com/rust-lang/rust-bindgen/issues/1651
        .layout_tests(false)
        // Avoid debug as dcap has packed structs which will give error E0133
        .no_debug("*")
        .newtype_enum("_sgx_ql_request_policy")
        .newtype_enum("_quote3_error_t")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
