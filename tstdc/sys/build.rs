// Copyright (c) 2022-2024 The MobileCoin Foundation

//! Builds the FFI function bindings for tstdc (trusted standard C) of the
//! Intel SGX SDK

fn main() {
    let link_path = mc_sgx_core_build::sgx_library_string();
    cargo_emit::rerun_if_changed!(link_path);
    cargo_emit::rustc_link_search!(link_path);
    cargo_emit::rustc_link_lib!("static=sgx_tstdc");

    let out_path = mc_sgx_core_build::build_output_dir();
    mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .blocklist_type("*")
        .allowlist_function("sgx_thread.*")
        .allowlist_function("sgx_alloc.*")
        .allowlist_function("sgx_spin.*")
        .allowlist_function("sgx_cpuid.*")
        .allowlist_function("sgx_.*rsrv.*")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
