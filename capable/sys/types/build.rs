// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI type bindings for the types used by libsgx_capable.{so,a}.

fn main() {
    let include_path = mc_sgx_core_build::sgx_include_path();
    cargo_emit::rerun_if_changed!(include_path);

    mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}", include_path))
        .allowlist_type("_sgx_device_status_t")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(mc_sgx_core_build::build_output_path().join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
