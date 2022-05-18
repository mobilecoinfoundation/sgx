// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI function bindings for tservice, (trusted service) of the
//! Intel Intel SGX SDK

use bindgen::Builder;
use cargo_emit::{rustc_link_lib, rustc_link_search};

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let sgx_suffix = mc_sgx_core_build::sgx_library_suffix();
    rustc_link_lib!(&format!("sgx_tservice{}", sgx_suffix));
    rustc_link_search!(&format!("{}/lib64", sgx_library_path));

    let bindings = Builder::default()
        .header_contents(
            "tservice.h",
            "#include <sgx_tseal.h>\n#include <sgx_dh.h>\n#include <sgx_utils.h>",
        )
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .blocklist_type("*")
        .allowlist_function("sgx_.*")
        // Need to block all of the crypto functions they come from the crypto
        // crate
        .blocklist_function("sgx_sha.*")
        .blocklist_function("sgx_rijndael.*")
        .blocklist_function("sgx_cmac.*")
        .blocklist_function("sgx_hmac.*")
        .blocklist_function("sgx_aes.*")
        .blocklist_function("sgx_ecc.*")
        .blocklist_function("sgx_.*ecdsa.*")
        .blocklist_function("sgx_.*rsa.*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = mc_sgx_core_build::build_output_path();
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
