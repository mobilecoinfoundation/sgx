// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the common SGX SDK types

use mc_sgx_core_build::SGXParseCallbacks;

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let builder = mc_sgx_core_build::sgx_builder()
        .header_contents(
            "core_types.h",
            "#include <sgx_error.h>\n#include <sgx_report.h>",
        )
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .newtype_enum("_status_t")
        .parse_callbacks(Box::new(SGXParseCallbacks))
        .allowlist_type("sgx_key_128bit_t")
        .allowlist_type("sgx_mac_t")
        .allowlist_type("sgx_isvfamily_id_t")
        .allowlist_type("sgx_isv_svn_t")
        .allowlist_type("sgx_isvext_prod_id_t")
        .allowlist_type("sgx_misc_select_t")
        .allowlist_type("_sgx_cpu_svn_t")
        .allowlist_type("sgx_prod_id_t")
        .allowlist_type("sgx_config_id_t")
        .allowlist_type("_sgx_measurement_t")
        .allowlist_type("sgx_config_svn_t")
        .allowlist_type("_sgx_key_id_t")
        .allowlist_type("_report_body_t")
        .allowlist_type("_sgx_report_data_t")
        .allowlist_type("_status_t")
        .allowlist_type("_target_info_t")
        .allowlist_type("_attributes_t")
        .allowlist_type("_report_t")
        .allowlist_type("_key_request_t");

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = mc_sgx_core_build::build_output_path();
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
