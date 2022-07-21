// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the FFI type bindings for the common SGX SDK types

use bindgen::{callbacks::ParseCallbacks, Builder};
use once_cell::sync::Lazy;

// Types that don't have an SGX qualifier.
//
// These types are of the form <name> and later typedefed to an `sgx_<name>`.
//
// ```C
//      typedef struct _foo_name {
//          int a;
//          float b;
//      } sgx_foo_name;
// ```
//
// To keep the noise out of the bindings, we use the underlying type and tell
// bindgen to map directly to `sgx_<name>` version.
static ALLOWED_UNDERLYING_TYPES: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "_status_t",
        "_target_info_t",
        "_attributes_t",
        "_report_t",
        "_key_request_t",
    ]
});

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        if ALLOWED_UNDERLYING_TYPES.contains(&name) {
            Some(format!("sgx{}", name))
        } else if name.starts_with("_sgx") {
            Some(name[1..].to_owned())
        } else {
            None
        }
    }
}

fn main() {
    let sgx_library_path = mc_sgx_core_build::sgx_library_path();
    let mut builder = Builder::default()
        .header_contents(
            "core_types.h",
            "#include <sgx_error.h>\n#include <sgx_report.h>",
        )
        .clang_arg(&format!("-I{}/include", sgx_library_path))
        .newtype_enum("_status_t")
        .parse_callbacks(Box::new(Callbacks))
        .ctypes_prefix("core::ffi")
        .use_core()
        .allowlist_type("sgx_key_128bit_t");

    for t in ALLOWED_UNDERLYING_TYPES.iter() {
        builder = builder.allowlist_type(t)
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = mc_sgx_core_build::build_output_path();
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
