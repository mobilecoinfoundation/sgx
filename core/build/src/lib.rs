// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use std::{env, path::PathBuf};

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";

#[cfg(feature = "hw")]
const SGX_SUFFIX: &str = "";
#[cfg(not(feature = "hw"))]
const SGX_SUFFIX: &str = "_sim";

/// Return the SGX library path.
///
/// Will first attempt to look at the environment variable `SGX_SDK`, if that
/// isn't present then `/opt/intel/sgxsdk` will be used.
pub fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}

/// Return the build output path.
///
pub fn build_output_path() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").expect("Missing env.OUT_DIR"))
}

/// Return the SGX library suffix
///
/// Some SGX libraries have a suffix for example `sgx_trts.a` versus
/// `sgx_trts_sim.a`.  This will result the suffix based on the presence of the
/// feature `hw`.
pub fn sgx_library_suffix() -> &'static str {
    SGX_SUFFIX
}

