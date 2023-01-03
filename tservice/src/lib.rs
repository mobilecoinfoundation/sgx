// Copyright (c) 2022-2023 MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations)]

extern crate alloc;

mod report;
mod seal;

pub use crate::{
    report::Report,
    seal::{SealedBuilder, Unseal},
};
