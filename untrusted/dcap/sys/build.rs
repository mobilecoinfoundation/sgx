// Copyright (c) 2022 The MobileCoin Foundation

//! Build the FFI function bindings for DCAP (Data Center Attestation Primitives)
#[cfg(any(feature = "generate", feature = "verify"))]
use {
    bindgen,
    cargo_emit::rustc_link_lib,
    std::{env, path::PathBuf},
};

fn main() {
    include_generate_if_configured();
    include_verify_if_configured();
}

fn include_generate_if_configured() {
    #[cfg(feature = "generate")]
    {
        rustc_link_lib!("sgx_dcap_ql");

        let bindings = bindgen::Builder::default()
            .header_contents("dcap_generate.h", "#include <sgx_dcap_ql_wrapper.h>")
            .blocklist_type("*")
            .allowlist_function("sgx_qe_.*")
            .allowlist_function("sgx_ql_.*")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings");

        let out_path = PathBuf::from(env::var("OUT_DIR").expect("Missing env.OUT_DIR"));
        bindings
            .write_to_file(out_path.join("generate_bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}

fn include_verify_if_configured() {
    #[cfg(feature = "verify")]
    {
        rustc_link_lib!("sgx_dcap_quoteverify");

        let bindings = bindgen::Builder::default()
            .header_contents("dcap_verify.h", "#include <sgx_dcap_quoteverify.h>")
            .blocklist_type("*")
            .allowlist_function("sgx_qv_.*")
            .parse_callbacks(Box::new(bindgen::CargoCallbacks))
            .generate()
            .expect("Unable to generate bindings");

        let out_path = PathBuf::from(env::var("OUT_DIR").expect("Missing env.OUT_DIR"));
        bindings
            .write_to_file(out_path.join("verify_bindings.rs"))
            .expect("Couldn't write bindings!");
    }
}
