// Copyright (c) 2022 The MobileCoin Foundation
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

/// The location to the test enclave.  This is determined at compile time.
/// As such moving the enclave binary after the fact will *not* update this
/// value.
pub static ENCLAVE: &str = concat!(env!("OUT_DIR"), "/libenclave.signed.so");

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
