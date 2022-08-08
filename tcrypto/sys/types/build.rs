// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the trusted crypto functions, (aes, rsa,
//! etc.), of the Intel SGX SDK

use bindgen::{callbacks::ParseCallbacks, Builder};

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        if name.starts_with("_sgx") {
            Some(name[1..].to_owned())
        } else {
            None
        }
    }
}

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let bindings = Builder::default()
        .header_contents("tcrypto_types.h", "#include <sgx_tcrypto.h>")
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .blocklist_function("*")
        .newtype_enum("sgx_generic_ecresult_t")
        .newtype_enum("sgx_rsa_result_t")
        .newtype_enum("sgx_rsa_key_type_t")
        .allowlist_type("_sgx_ec256_.*")
        .allowlist_type("_sgx_rsa3072_.*")
        .allowlist_type("sgx_rsa3072_signature_t")
        .allowlist_type("sgx_rsa_result_t")
        .allowlist_type("sgx_rsa_key_type_t")
        .allowlist_type("sgx_sha.*")
        .allowlist_type("sgx_cmac_.*")
        .allowlist_type("sgx_hmac_.*")
        .allowlist_type("sgx_aes_.*")
        .allowlist_type("sgx_ecc_.*")
        .allowlist_type("sgx_generic_ecresult_t")
        .parse_callbacks(Box::new(Callbacks))
        .ctypes_prefix("core::ffi")
        .use_core()
        .generate()
        .expect("Unable to generate bindings");

    let out_path = mc_sgx_core_build::build_output_path();
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
