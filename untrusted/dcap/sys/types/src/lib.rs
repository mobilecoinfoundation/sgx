// Copyright (c) 2022 The MobileCoin Foundation
//! FFI types for DCAP (Data Center Attestation Primitives) quote generation,
//! see
//! https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf

#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    clippy::missing_safety_doc
)]

use std::fmt;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl fmt::Debug for _quote3_error_t {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hexify the output.  The default debug output is
        // `_quote3_error_t(<int>)` while the error code definitions are in hex.
        write!(fmt, "_quote3_error_t({:x})", self.0)
    }
}
