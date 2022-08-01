// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use std::{env, path::PathBuf};

/// Return the SGX library path.
///
/// When `vendored` feature is on this will provide the path from the
/// vendored build.
///
/// Otherwise will first attempt to look at the environment variable `SGX_SDK`,
/// if that isn't present then `/opt/intel/sgxsdk` will be used.
pub fn sgx_library_path() -> String {
    cfg_if::cfg_if! {
        if #[cfg(feature = "vendored")] {
            mc_sgx_core_source::sgx_library_path()
        } else {
            env::var("SGX_SDK").unwrap_or_else(|_| "/opt/intel/sgxsdk".into())
        }
    }
}

/// Return the build output path.
pub fn build_output_path() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").expect("Missing env.OUT_DIR"))
}

/// Return the SGX library suffix
///
/// Some SGX libraries have a suffix for example `sgx_trts.a` versus
/// `sgx_trts_sim.a`.  This will result the suffix based on the presence of the
/// feature `hw`.
pub fn sgx_library_suffix() -> &'static str {
    // See https://doc.rust-lang.org/cargo/reference/features.html#build-scripts
    // for description of `CARGO_FEATURE_<name>`
    match env::var("CARGO_FEATURE_HW") {
        Ok(_) => "",
        _ => "_sim",
    }
}
