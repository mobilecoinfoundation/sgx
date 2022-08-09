// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the common SGX SDK types

// The types to generate bindings for.
//
// To keep the noise out of the bindings, we use the underlying type and tell
// bindgen to map directly to `sgx_<name>` version.
//
// For example `_foo_name` would be the underlying type:
// ```C
//      typedef struct _foo_name {
//          int a;
//          float b;
//      } sgx_foo_name;
// ```
const CORE_TYPES: &[&str] = &[
    "_attributes_t",
    "_key_request_t",
    "_report_body_t",
    "_report_t",
    "_sgx_cpu_svn_t",
    "_sgx_key_id_t",
    "_sgx_measurement_t",
    "_sgx_report_data_t",
    "_status_t",
    "_target_info_t",
    "sgx_config_id_t",
    "sgx_config_svn_t",
    "sgx_isv_svn_t",
    "sgx_isvext_prod_id_t",
    "sgx_isvfamily_id_t",
    "sgx_key_128bit_t",
    "sgx_mac_t",
    "sgx_misc_select_t",
    "sgx_prod_id_t",
];

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let mut builder = mc_sgx_core_build::sgx_builder()
        .header_contents(
            "core_types.h",
            "#include <sgx_error.h>\n#include <sgx_report.h>",
        )
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .newtype_enum("_status_t");

    for t in CORE_TYPES.iter() {
        builder = builder.allowlist_type(t)
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = mc_sgx_core_build::build_output_path();
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
