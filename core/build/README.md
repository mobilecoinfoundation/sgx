# MobileCoin SGX: Build Utilities

[![Project Chat][chat-image]][chat-link]<!--
-->![License][license-image]<!--
-->![Target][target-image]<!--
-->[![Crates.io][crate-image]][crate-link]<!--
-->[![Docs Status][docs-image]][docs-link]<!--
-->[![Dependency Status][deps-image]][deps-link]

Utilities for compiling FFI wrappers to SGX libraries.

## Environment Variables

Below are environment variables that affect the building of the SGX FFI
wrappers.

- `SGX_SDK` The path to the Intel SGX SDK. Provides:
  
  1. The location of the SGX SDK headers.
  
     Note: the DCAP headers are assumed to be in the default system include path
  2. The location of the SGX SDK libraries for linking
  
  When `SGX_SDK` is not set:

  1. The vendored local directory `headers/` will be used for compile time
     includes
  2. `/opt/intel/sgxsdk` will be used as the linking directory for SGX SDK
     libraries

- `CFLAGS` - Used when generating the rust bindings. Useful to specify
  system include paths. Multiple arguments can be separated with whitespace.
  This does **not** support escaped whitespace as specified in
  <https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html>

[crate-image]: https://img.shields.io/crates/v/mc-sgx-core-build.svg?style=flat-square
[crate-link]: https://crates.io/crates/mc-sgx-core-build
[license-image]: https://img.shields.io/crates/l/mc-sgx-core-build?style=flat-square
[target-image]: https://img.shields.io/badge/target-any-brightgreen?style=flat-square
[chat-image]: https://img.shields.io/discord/844353360348971068?style=flat-square
[chat-link]: https://mobilecoin.chat
[docs-image]: https://img.shields.io/docsrs/mc-sgx-core-build?style=flat-square
[docs-link]: https://docs.rs/crate/mc-sgx-core-build
[deps-image]: https://deps.rs/crate/mc-sgx-core-build/0.7.5/status.svg?style=flat-square
[deps-link]: https://deps.rs/crate/mc-sgx-core-build/0.7.5
