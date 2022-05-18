// Copyright (c) 2022 The MobileCoin Foundation
//! FFI types for the SGX SDK trusted service library (tservice).

#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

// Nesting to work around clippy warnings, see
// https://github.com/rust-lang/rust-bindgen/issues/1470
#[allow(clippy::missing_safety_doc)]
mod bindings {
    // include!(..);
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}
pub use bindings::*;
