// Copyright (c) 2022-2025 The MobileCoin Foundation
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]
//! Contains format utilities for formatting Hex representations of integers and byte arrays.

use core::fmt::Formatter;

/// A helper method that displays a u32 as Hex with a "_" delimiter.
pub fn fmt_hex(src: &[u8], f: &mut Formatter) -> core::fmt::Result {
    let prefix = "0x";
    let separators = ::core::iter::once(prefix).chain(::core::iter::repeat("_"));
    let segments = separators.zip(src.chunks(2));
    for (separator, chunk) in segments {
        write!(f, "{separator}")?;
        for byte in chunk {
            write!(f, "{:02X}", byte)?;
        }
    }

    Ok(())
}
