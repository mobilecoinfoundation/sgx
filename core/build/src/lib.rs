// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use bindgen::{callbacks::ParseCallbacks, Builder, EnumVariation};
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

/// Normalizes a type encountered by bindgen
///
/// Provides a default [bindgen::callbacks::ParserCallbacks::item_name]
/// implementation that works with most SGX types.
/// The type should come back in the form of `sgx_<main_text_from_c_interface>`
///
/// Returns `None` if the type is already normalized
///
/// # Arguments
/// * `name` - The name of the type to determine the bindgen name of.
pub fn sgx_normalize_item_name(name: &str) -> Option<String> {
    if name.starts_with("_sgx") || name.starts_with("_tee") {
        Some(name[1..].to_owned())
    } else if name.starts_with('_') {
        Some(format!("sgx{}", name))
    } else {
        None
    }
}

/// Returns a builder configured with the defaults for using bindgen with the
/// SGX libraries.
pub fn sgx_builder() -> Builder {
    Builder::default()
        .derive_copy(true)
        .derive_debug(true)
        .derive_default(true)
        .derive_eq(true)
        .derive_hash(true)
        .derive_ord(true)
        .derive_partialeq(true)
        .derive_partialord(true)
        // Comments can cause doc tests to fail, see https://github.com/rust-lang/rust-bindgen/issues/1313
        .generate_comments(false)
        .default_enum_style(EnumVariation::Consts)
        .prepend_enum_name(false)
        .use_core()
        .ctypes_prefix("core::ffi")
        .allowlist_recursively(false)
        .parse_callbacks(Box::new(SgxParseCallbacks))
}

/// SGXParseCallbacks to be used with [bindgen::Builder::parse_callbacks]
///
/// This provides a default implementation for most of the SGX libraries
#[derive(Debug)]
pub struct SgxParseCallbacks;

impl ParseCallbacks for SgxParseCallbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        sgx_normalize_item_name(name)
    }
}

/// Return the SGX library path.
///
/// Will first attempt to look at the environment variable `SGX_SDK`, if that
/// isn't present then `/opt/intel/sgxsdk` will be used.
pub fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

/// Return the build output path.
pub fn build_output_path() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").expect("Missing env.OUT_DIR"))
}

/// Return the SGX library suffix
///
/// Some SGX libraries have a suffix for example `sgx_trts.a` versus
/// `sgx_trts_sim.a`.  This will result the suffix based on the presence of the
/// feature `sim`.
pub fn sgx_library_suffix() -> &'static str {
    // See https://doc.rust-lang.org/cargo/reference/features.html#build-scripts
    // for description of `CARGO_FEATURE_<name>`
    match env::var("CARGO_FEATURE_SIM") {
        Ok(_) => "_sim",
        _ => "",
    }
}
