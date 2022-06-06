// Copyright (c) 2022 The MobileCoin Foundation
//! FFI functions for DCAP (Data Center Attestation Primitives)
//! https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf

#[cfg(feature = "generate")]
mod generate;
#[cfg(feature = "generate")]
pub use generate::*;

#[cfg(feature = "verify")]
mod verify;
#[cfg(feature = "verify")]
pub use verify::*;
