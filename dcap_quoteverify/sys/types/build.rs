// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the dcap quoteverify library of the Intel
//! SGX SDK

use bindgen::callbacks::ParseCallbacks;

const DCAP_QUOTEVERIFY_TYPES: &[&str] = &[
    "sgx_qv_path_type_t",
    "_sgx_ql_qv_result_t",
    "_sgx_ql_qv_supplemental_t",
    "_pck_cert_flag_enum_t",
    "_sgx_ql_att_key_id_param_t",
    "_sgx_ql_att_id_list_t",
    "_sgx_ql_qe_report_info_t",
    "_quote_nonce",
    "_sgx_ql_att_key_id_list_header_t",
    "_sgx_att_key_id_ext_t",
    "_sgx_ql_att_key_id_t",
];

/// ParseCallbacks to be used with [bindgen::Builder::parse_callbacks]
#[derive(Debug)]
pub struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        // The `_quote_nonce` is an outlier name missing the trailing `_t`
        if name == "_quote_nonce" {
            Some("sgx_quote_nonce_t".to_owned())
        } else {
            mc_sgx_core_build::normalize_item_name(name)
        }
    }
}

fn main() {
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .blocklist_function("*")
        .parse_callbacks(Box::new(Callbacks));

    for t in DCAP_QUOTEVERIFY_TYPES {
        builder = builder.allowlist_type(t);
    }

    let out_path = mc_sgx_core_build::build_output_path();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
