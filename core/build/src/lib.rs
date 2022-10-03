// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use bindgen::{
    callbacks::{IntKind, ParseCallbacks},
    Builder, EnumVariation,
};
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
const STRIP_UNDERSCORE_PREFIX: &[&str] = &["_sgx", "_tee", "_quote3", "_pck", "_rsa"];

/// Normalizes a type encountered by bindgen
///
/// Provides a default [bindgen::callbacks::ParseCallbacks::item_name]
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
        .derive_copy(false)
        .derive_debug(false)
        .default_enum_style(EnumVariation::NewType { is_bitfield: false })
        .prepend_enum_name(false)
        .use_core()
        .ctypes_prefix("core::ffi")
        .allowlist_recursively(false)
        .generate_comments(false)
        .parse_callbacks(Box::new(SgxParseCallbacks::default()))
}

/// SGXParseCallbacks to be used with [bindgen::Builder::parse_callbacks]
///
/// This provides a default implementation for most of the SGX libraries
#[derive(Debug, Default)]
pub struct SgxParseCallbacks {
    // types that are copyable and thus should derive `Copy`
    //
    // These are usually small types or packed types
    copyable_types: Vec<String>,

    // types that need to derive `Default`
    default_types: Vec<String>,

    // types that are enums
    enum_types: Vec<String>,

    // Dynamically Sized types
    dynamically_sized_types: Vec<String>,
}

impl SgxParseCallbacks {
    /// Types that are enums
    ///
    /// Bindgen derives some attributes by default for enums, in order to
    /// properly handle them they must be known.
    ///
    /// Note: Enums will also derive `Copy`, there is no need to specify in
    ///       [`derive_copy()`](SgxParseCallbacks::derive_copy())
    ///
    /// # Arguments
    /// * `enum_types` - Types that are enums.
    pub fn enum_types<'a, E, I>(mut self, enum_types: I) -> Self
    where
        I: IntoIterator<Item = &'a E>,
        E: ToString + 'a + ?Sized,
    {
        let enum_types = enum_types
            .into_iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        self.enum_types.extend(enum_types.clone());

        // Enum types (from C interfaces) are small enough to always be
        // copyable.
        self.copyable_types.extend(enum_types);

        self
    }

    /// Types to derive copy for, usually packed types
    ///
    /// # Arguments
    /// * `copyable_types` - Types to derive copy for.
    pub fn derive_copy<'a, E, I>(mut self, copyable_types: I) -> Self
    where
        I: IntoIterator<Item = &'a E>,
        E: ToString + 'a + ?Sized,
    {
        self.copyable_types
            .extend(copyable_types.into_iter().map(ToString::to_string));
        self
    }

    /// Types to derive default for
    ///
    /// # Arguments
    /// * `default_types` - Types to derive default for.
    pub fn derive_default<'a, E, I>(mut self, default_types: I) -> Self
    where
        I: IntoIterator<Item = &'a E>,
        E: ToString + 'a + ?Sized,
    {
        self.default_types
            .extend(default_types.into_iter().map(ToString::to_string));
        self
    }

    /// Dynamically Sized Types
    ///
    /// # Arguments
    /// * `dynamically_sized_types` - Types that are dynamically sized.  Due to
    ///   the dynamic size certain traits like `Eq` can't be derived.
    pub fn dynamically_sized_types<'a, E, I>(mut self, dynamically_sized_types: I) -> Self
    where
        I: IntoIterator<Item = &'a E>,
        E: ToString + 'a + ?Sized,
    {
        self.dynamically_sized_types
            .extend(dynamically_sized_types.into_iter().map(ToString::to_string));
        self
    }
}

impl ParseCallbacks for SgxParseCallbacks {
    fn item_name(&self, name: &str) -> Option<String> {
        normalize_item_name(name)
    }

    fn add_derives(&self, name: &str) -> Vec<String> {
        let mut attributes = vec![];

        if self.default_types.iter().any(|n| *n == name) {
            attributes.push("Default");
        }

        // The [enum_types] method adds enums to the [copyable_types]
        if self.copyable_types.iter().any(|n| *n == name) {
            attributes.push("Copy");
        }

        if !self.dynamically_sized_types.iter().any(|n| *n == name) {
            // For dynamically sized types we don't even derive Debug, because
            // they are often times packed and packed types can't derive Debug
            // without deriving Copy, however by the dynamic nature one can't
            // derive Copy
            attributes.push("Debug");
            if !self.enum_types.iter().any(|n| *n == name) {
                attributes.extend(["Clone", "Hash", "PartialEq", "Eq"]);
            }
        };

        attributes.into_iter().map(String::from).collect::<Vec<_>>()
    }

    fn int_macro(&self, name: &str, _value: i64) -> Option<IntKind> {
        const USIZE_SUFFIXES: &[&str] = &["_SIZE", "_BYTES", "_IDX", "_COUNT"];
        if USIZE_SUFFIXES.iter().any(|suffix| name.ends_with(suffix)) {
            Some(IntKind::Custom {
                name: "usize",
                is_signed: false,
            })
        } else if name.starts_with("SGX_KEYSELECT_") || name.starts_with("SGX_KEYPOLICY_") {
            Some(IntKind::U16)
        } else {
            None
        }
    }
}

/// Return the SGX SDK path, if it exists.
fn sgx_sdk_dir() -> Option<PathBuf> {
    env::var("SGX_SDK").ok().map(PathBuf::from)
}

/// This constant contains the manifest dir of crate-build, which will contain
/// the headers, which allows all the headers to live in one dir, rather than
/// scattered about the repo.
const CARGO_MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");

/// Return the SGX include path
///
/// Will first attempt to look at the environment variable `SGX_SDK`, if that
/// isn't present then the "headers" directory of this crate will be used.
pub fn sgx_include_dir() -> PathBuf {
    sgx_sdk_dir()
        .map(|sdk_path| sdk_path.join("include"))
        .unwrap_or_else(|| PathBuf::from(CARGO_MANIFEST_DIR).join("headers"))
}

/// Return the SGX include path as a string.
///
/// Calls sgx_include_dir() and converts to a string.
pub fn sgx_include_string() -> String {
    sgx_include_dir()
        .to_str()
        .expect("SGX_SDK contained invalid UTF-8 that wasn't caught by rust")
        .to_owned()
}

/// Return the SGX library path.
///
/// Will first attempt to look at the environment variable `SGX_SDK`, if that
/// isn't present then `/opt/intel/sgxsdk` will be used.
pub fn sgx_library_dir() -> PathBuf {
    // As of INTEL-SA-00615, 32-on-64bit enclaves are insecure, so we don't support
    // them.
    sgx_sdk_dir()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SGX_SDK_PATH))
        .join("lib64")
}

/// Return the SGX library path as a string
///
/// Calls sgx_library_dir() and converts to a string.
pub fn sgx_library_string() -> String {
    sgx_library_dir()
        .to_str()
        .expect("SGX_SDK contained invalid UTF-8 that wasn't caught by rust")
        .to_owned()
}

/// Return the SGX binary path.
///
/// Will first attempt to look at the environment variable `SGX_SDK`, if that
/// isn't present then `/opt/intel/sgxsdk` will be used.
pub fn sgx_bin_x64_dir() -> PathBuf {
    let mut retval = sgx_sdk_dir().unwrap_or_else(|| PathBuf::from(DEFAULT_SGX_SDK_PATH));
    retval.push("bin");
    retval.push("x64");
    retval
}

/// Return the build output path.
pub fn build_output_dir() -> PathBuf {
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
