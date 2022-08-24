// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the dcap quote library of the Intel SGX SDK

use mc_sgx_core_build::SgxParseCallbacks;

const DCAP_QL_TYPES: &[&str] = &[
    "_sgx_ql_att_key_id_param_t",
    "_sgx_ql_att_id_list_t",
    "_sgx_ql_qe_report_info_t",
    "sgx_ql_path_type_t",
];

fn main() {
    let include_path = mc_sgx_core_build::sgx_include_string();
    cargo_emit::rerun_if_changed!(include_path);

    let callback = SgxParseCallbacks::new(["sgx_ql_path_type_t"].iter());
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}", include_path))
        .parse_callbacks(Box::new(callback))
        .blocklist_function("*");

    for t in DCAP_QL_TYPES {
        builder = builder.allowlist_type(t);
    }

    let out_path = mc_sgx_core_build::build_output_dir();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
