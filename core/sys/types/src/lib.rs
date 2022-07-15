// Copyright (c) 2022 The MobileCoin Foundation
//! Exported SGX FFI types

#![feature(core_ffi_c)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
