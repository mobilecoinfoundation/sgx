// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for tservice, (trusted service) of the Intel
//! SGX SDK

use bindgen::{callbacks::ParseCallbacks, Builder};

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        match name {
            "_aes_gcm_data_t" => Some("sgx_aes_gcm_data_t".to_owned()),
            "_sealed_data_t" => Some("sgx_sealed_data_t".to_owned()),
            name => {
                if name.starts_with("_sgx") || name.starts_with("_tee") {
                    Some(name[1..].to_owned())
                } else {
                    None
                }
            }
        }
    }
}

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let bindings = Builder::default()
        .header_contents(
            "tservice.h",
            "#include <sgx_tseal.h>\n#include <sgx_dh.h>\n#include <sgx_utils.h>",
        )
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .blocklist_type("sgx_.*")
        .allowlist_type("_aes_gcm_data_t")
        .allowlist_type("_sealed_data_t")
        .allowlist_type("_sgx_dh_.*")
        .allowlist_type("_sgx_report2_mac_struct_t")
        // `_sgx_dh_msg3_body_t` is a packed struct that bindgen can't derive
        // Copy for, which will result in E0133.
        .no_debug("_sgx_dh_msg3_body_t")
        .parse_callbacks(Box::new(Callbacks))
        .ctypes_prefix("core::ffi")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = mc_sgx_core_build::build_output_path();
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
