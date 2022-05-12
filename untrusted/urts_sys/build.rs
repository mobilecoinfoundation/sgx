// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI bindings for the untrusted side of the Intel SGX SDK
extern crate bindgen;
use cargo_emit::{rustc_link_lib, rustc_link_search};
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

fn sgx_library_suffix() -> &'static str {
    match () {
        #[cfg(feature = "hw")]
        () => "",
        #[cfg(not(feature = "hw"))]
        () => "_sim",
    }
}

fn main() {
    let sim_suffix = sgx_library_suffix();
    rustc_link_lib!(&format!("sgx_urts{}", sim_suffix));
    rustc_link_lib!(&format!("sgx_launch{}", sim_suffix));
    rustc_link_search!(&format!("{}/lib64", sgx_library_path()));

    // TODO: This currently brings in *all* of the urts types into one binding.
    //       Need to evaluate if all the types should be intermixed here
    let bindings = bindgen::Builder::default()
        .header_contents("urts.h", "#include <sgx_urts.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path()))
        .blocklist_type("*")
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
