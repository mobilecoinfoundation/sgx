// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI type bindings for the types used by libsgx_capable.{so,a}.

use bindgen::{
    callbacks::{IntKind, ParseCallbacks},
    Builder, EnumVariation,
};
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

#[derive(Debug)]
struct Callbacks;

impl ParseCallbacks for Callbacks {
    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        if name.ends_with("_SIZE") || name.ends_with("_BYTES") {
            Some(IntKind::Custom {
                name: "usize",
                is_signed: false,
            })
        } else {
            None
        }
    }

    fn item_name(&self, name: &str) -> Option<String> {
        cargo_emit::warning!("Processing {}", name);
        if name.starts_with("_sgx_") {
            Some(name[1..].to_owned())
        } else if name.starts_with('_') {
            let mut retval = "sgx".to_owned();
            retval.push_str(name);
            Some(retval)
        } else {
            None
        }
    }
}

fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

fn main() {
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    Builder::default()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}/include", sgx_library_path()))
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_ord(true)
        .derive_partialeq(true)
        .derive_partialord(true)
        .default_enum_style(EnumVariation::Consts)
        .prepend_enum_name(false)
        .use_core()
        .ctypes_prefix("core::ffi")
        .allowlist_recursively(false)
        .blocklist_function("*")
        .allowlist_type("_sgx_device_status_t")
        .parse_callbacks(Box::new(Callbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
