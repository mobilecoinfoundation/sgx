// Copyright (c) 2022 The MobileCoin Foundation

const SGX_SDK_PATH: &str = include_str!(concat!(env!("OUT_DIR"), "/sgx_sdk_path.txt"));

pub fn sgx_library_path() -> String {
    SGX_SDK_PATH.to_string()
}
