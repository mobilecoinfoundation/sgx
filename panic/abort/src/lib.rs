// Copyright 2021 MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![feature(lang_items)]

use core::panic::PanicInfo;

/// The panic implementation.
///
/// This is required by no_std libraries (on the rust side), and calls
/// `abort()` in a previously imported `libsgx_tcxx.a` (on the SGX side).
#[lang = "panic_impl"]
#[no_mangle]
pub extern "C" fn panic(_info: &PanicInfo) -> ! {
    extern "C" {
        fn abort() -> !;
    }

    unsafe { abort() }
}

/// Exception Handling Personality Language Item.
///
/// This is required to inject panic-handling into an application with only
/// libcore support.
#[lang = "eh_personality"]
#[no_mangle]
pub extern "C" fn rust_eh_personality() {}
