// Copyright (c) 2022 The MobileCoin Foundation

/// Errors seen when converting to, or from, rust for the SGX types
#[derive(Debug)]
pub enum Error {
    /// Enum out of range
    /// Happens when a value that is not represented by the known C enum values.
    UnknownEnumValue(i64),
}
