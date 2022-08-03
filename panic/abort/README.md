# MobileCoin SGX: Panic-Abort

Aborting panic handler for Intel-SGX enclaves.

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![GPLv3.0 Licensed][license-image]
![Rust Version][rustc-image]
[![Project Chat][chat-image]][chat-link]
[![Crates.io Downloads][downloads-image]][crate-link]
[![Build Status][build-image]][build-link]

This crate provides a panic handler implementation intended to be executed
inside an SGX enclave. Specifically, it will provide the
required `rust_eh_personality()` and `#![panic_handler]` methods to satisfy the
linker for a `#![no_std]` environment. As a result, this crate will

This crate currently requires independent linkage to the `libsgx_trts.a`
library, which provides the `abort()` call we use to mark the enclave dead. The
goal for all crates in this repository is to handle the intricate linkage
requirements of the Intel SGX SDK automagically, but that is not in place yet,
so users of this crate will need to link it themselves for now.

[crate-image]: https://img.shields.io/crates/v/mc-sgx-panic-abort?style=for-the-badge
[crate-link]: https://crates.io/crates/mc-sgx-panic-abort
[docs-image]: https://img.shields.io/docsrs/mc-sgx-panic-abort/latest?style=for-the-badge
[docs-link]: https://docs.rs/mc-sgx-panic-abort/
[license-image]: https://img.shields.io/github/license/mobilecoinfoundation/sgx?style=for-the-badge
[rustc-image]: https://img.shields.io/badge/rustc-nightly-orange.svg?style=for-the-badge&logo=rust
[chat-image]: https://img.shields.io/discord/844353360348971068.svg?style=for-the-badge
[chat-link]: https://discord.gg/4kP8ftbVfA
[downloads-image]: https://img.shields.io/crates/d/mc-sgx-panic-abort.svg?style=for-the-badge
[build-image]: https://img.shields.io/github/workflow/status/mobilecoinfoundation/sgx/panic-abort?style=for-the-badge
[build-link]: https://github.com/mobilecoinfoundation/sgx/actions
