// Copyright (c) 2022 MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations)]

extern crate alloc;

mod seal;

pub use crate::seal::SealedBuilder;
