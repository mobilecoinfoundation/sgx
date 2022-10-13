// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI type bindings for the types used by libsgx_capable.{so,a}.

use mc_sgx_core_build::SgxParseCallbacks;

fn main() {
    let callback = SgxParseCallbacks::default().enum_types(["sgx_device_status_t"]);

    mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .allowlist_type("_sgx_device_status_t")
        .parse_callbacks(Box::new(callback))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(mc_sgx_core_build::build_output_dir().join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
