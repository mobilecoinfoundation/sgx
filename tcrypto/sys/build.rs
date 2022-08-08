// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI function bindings for trusted crypto (tcrypto) of the
//! Intel SGX SDK

use bindgen::Builder;
use cargo_emit::{rustc_link_lib, rustc_link_search};

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    rustc_link_lib!("sgx_tcrypto");
    rustc_link_search!(&format!("{}/lib64", sgx_library_path));

    let bindings = Builder::default()
        .header_contents("tcrypto.h", "#include <sgx_tcrypto.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .blocklist_type("*")
        .allowlist_function("sgx_sha.*")
        .allowlist_function("sgx_rijndael.*")
        .allowlist_function("sgx_cmac.*")
        .allowlist_function("sgx_hmac.*")
        .allowlist_function("sgx_aes.*")
        .allowlist_function("sgx_ecc.*")
        .allowlist_function("sgx_.*ecdsa.*")
        .allowlist_function("sgx_.*rsa.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .ctypes_prefix("core::ffi")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = mc_sgx_core_build::build_output_path();
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
