// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use bindgen::{callbacks::ParseCallbacks, Builder, EnumVariation};
use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

/// Type name prefixes that need the underscore prefix stripped from them.
///
/// For example `_foo_bar` should be `foo_bar`.
///
/// While it would be nice to add the `sgx` prefix to any non `_sgx` named type,
/// the name does not propagate to the types used in the generated bindings.
/// For example mapping `_foo_bar` to `sgx_foo_bar` would fail because the
/// following function would still be looking for `foo_bar`.
/// ```C
/// void some_function(foo_bar arg);
/// ```
const STRIP_UNDERSCORE_PREFIX: &[&str] = &["_sgx", "_tee", "_quote3", "_pck"];

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
pub fn normalize_item_name(name: &str) -> Option<String> {
    let mut name = name.to_string();

    // all of the exposed sgx types end in `_t`, but at times the underlying
    // type may be missing it.
    if !name.ends_with("_t") {
        name.push_str("_t");
    }

    if STRIP_UNDERSCORE_PREFIX
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        name.strip_prefix('_').map(str::to_string)
    } else if name.starts_with('_') {
        name.insert_str(0, "sgx");
        Some(name)
    } else {
        None
    }
}

/// Returns a builder configured with the defaults for using bindgen with the
/// SGX libraries.
pub fn sgx_builder() -> Builder {
    Builder::default()
        // Copy will be provided by the `add_derives()` in `SgxParseCallbacks`
        .derive_copy(false)
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
        .parse_callbacks(Box::new(SgxParseCallbacks::default()))
}

/// SGXParseCallbacks to be used with [bindgen::Builder::parse_callbacks]
///
/// This provides a default implementation for most of the SGX libraries
#[derive(Debug, Default)]
pub struct SgxParseCallbacks {
    // types that are blocklisted from deriving Clone for.
    //
    // These may either already have the Clone attribute from bindgen, or they
    // can't derive clone due to having non cloneable default types like
    // `__IncompleteArrayField`.
    blocklisted_clone_types: Vec<String>,
}

impl SgxParseCallbacks {
    /// SGXParseCallbacks to be used with [bindgen::Builder::parse_callbacks]
    ///
    /// # Arguments
    /// * `blocklisted_clone_types` - Types to blocklist from deriving `Clone`.
    pub fn new<I>(blocklisted_clone_types: I) -> Self
    where
        I: Iterator,
        I::Item: AsRef<str>,
        I::Item: ToOwned,
    {
        let blocklisted_clone_types = blocklisted_clone_types
            .map(|s| s.as_ref().to_owned())
            .collect::<Vec<_>>();
        Self {
            blocklisted_clone_types,
        }
    }

    // Returns the derive attributes needed to implement `Clone` on `name`, if
    // `name` should implement clone.
    //
    // If `name` shouldn't derive `Clone` returns an empty vector.
    //
    // # Arguments
    // * `name` - The name of the type to check for deriving `Clone`.  The name
    //  is expected to be the _final_ name after any normalization,
    //  [bindgen::Builder::ParceCallbacks::item_name]
    fn maybe_derive_clone(&self, name: &str) -> Vec<String> {
        if self.blocklisted_clone_types.iter().any(|n| *n == name) {
            vec![]
        } else {
            // In order to support packed types we also need to derive `Copy`,
            // https://github.com/rust-lang/rust/issues/82523
            vec!["Clone".to_string(), "Copy".to_string()]
        }
    }
}

impl ParseCallbacks for SgxParseCallbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        normalize_item_name(name)
    }

    fn add_derives(&self, name: &str) -> Vec<String> {
        let mut derives = vec![];

        derives.append(&mut self.maybe_derive_clone(name));

        derives
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
