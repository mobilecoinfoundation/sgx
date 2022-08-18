// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![feature(c_size_t)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

pub use core::ffi::c_size_t as size_t;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
