// Copyright (c) 2022 The MobileCoin Foundation

//! Build the FFI function bindings for DCAP (Data Center Attestation Primitives)
//! quote generation
extern crate bindgen;
use cargo_emit::rustc_link_lib;
use std::{env, path::PathBuf};

fn main() {
    rustc_link_lib!("sgx_dcap_quoteverify");
    rustc_link_lib!("sgx_dcap_ql");

    let bindings = bindgen::Builder::default()
        //TODO: turn this into separate generation and verification crates
        .header_contents(
            "dcap_qv.h",
            "#include <sgx_dcap_quoteverify.h>\n#include <sgx_dcap_ql_wrapper.h>",
        )
        .blocklist_type("*")
        .allowlist_function("sgx_.*")
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
