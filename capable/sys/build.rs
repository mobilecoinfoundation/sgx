// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Builds the FFI type bindings for the types used by libsgx_capable.{so,a}.

fn main() {
    let link_path = mc_sgx_core_build::sgx_library_string();
    cargo_emit::rerun_if_changed!(link_path);
    cargo_emit::rustc_link_search!(link_path);
    cargo_emit::rustc_link_lib!("static=sgx_capable");

    mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .allowlist_function("sgx_is_capable")
        .allowlist_function("sgx_cap_enable_device")
        .allowlist_function("sgx_cap_get_status")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(mc_sgx_core_build::build_output_dir().join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
