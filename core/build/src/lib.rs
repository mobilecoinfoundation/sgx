// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use std::env;

static DEFAULT_SGX_SDK_PATH: &str = "/opt/intel/sgxsdk";


/// Get the SGX library path.
///
/// Will first attempt to look at the environment variable `SGX_SDK`, if that
/// isn't present then `/opt/intel/sgxsdk` will be used.
pub fn sgx_library_path() -> String {
    env::var("SGX_SDK").unwrap_or_else(|_| DEFAULT_SGX_SDK_PATH.into())
}
