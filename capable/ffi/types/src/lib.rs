// Copyright (c) 2018-2020 MobileCoin Inc.

//! FFI type bindings for the types used by libsgx_capable.{so,a}.

#![no_std]
#![allow(non_camel_case_types)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
