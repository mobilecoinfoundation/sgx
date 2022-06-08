// Copyright (c) 2022 The MobileCoin Foundation
//! Rust wrappers for DCAP (Data Center Attestation Primitives) quotes

mod error;
mod quote;

#[cfg(feature = "generate")]
mod generate;
#[cfg(feature = "verify")]
mod verify;

pub use error::Error;
pub use quote::Quote;

#[cfg(feature = "generate")]
pub use generate::Generate;
#[cfg(feature = "verify")]
pub use verify::Verify;
