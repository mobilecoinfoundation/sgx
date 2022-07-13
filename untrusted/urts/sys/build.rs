// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI bindings for the untrusted side of the Intel SGX SDK
use bindgen::Builder;
use cargo_emit::{rustc_link_lib, rustc_link_search};

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let sgx_suffix = mc_sgx_core_build::sgx_library_suffix();
    rustc_link_lib!(&format!("sgx_urts{}", sgx_suffix));
    rustc_link_lib!(&format!("sgx_launch{}", sgx_suffix));
    rustc_link_search!(&format!("{}/lib64", sgx_library_path));

    let bindings = Builder::default()
        .header_contents("urts.h", "#include <sgx_urts.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .blocklist_type("*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = mc_sgx_core_build::build_output_path();
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
