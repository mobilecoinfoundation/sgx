// Copyright (c) 2022-2023 The MobileCoin Foundation
//! Builds the FFI function bindings for dcap tvl library of the Intel SGX SDK

const DCAP_TVL_FUNCTIONS: &[&str] = &["sgx_tvl_verify_qve_report_and_identity"];

fn main() {
    let link_path = mc_sgx_core_build::sgx_library_string();
    cargo_emit::rustc_link_search!(link_path);
    cargo_emit::rerun_if_changed!(link_path);
    cargo_emit::rustc_link_lib!("static=sgx_dcap_tvl");

    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .blocklist_type("*");

    for f in DCAP_TVL_FUNCTIONS {
        builder = builder.allowlist_function(f);
    }

    let out_path = mc_sgx_core_build::build_output_dir();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
