// Copyright (c) 2022 The MobileCoin Foundation

//! Exported SGX FFI types

#![no_std]
#![allow(
    clippy::missing_safety_doc,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl Clone for sgx_key_id_t {
    fn clone(&self) -> sgx_key_id_t {
        sgx_key_id_t { id: self.id }
    }
}
