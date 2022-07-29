// Copyright (c) 2022 The MobileCoin Foundation

use std::env;

pub fn sgx_library_path() -> String {
    env::var("DEP_OPENSSL_VERSION_NUMBER").unwrap_or_else(|_| "TACOS".to_string())
}
