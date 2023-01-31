# MobileCoin's Rust Interface for uRTS

[![Project Chat][chat-image]][chat-link]<!--
-->![License][license-image]<!--
-->![Target][target-image]<!--
-->[![Crates.io][crate-image]][crate-link]<!--
-->[![Docs Status][docs-image]][docs-link]<!--
-->[![Dependency Status][deps-image]][deps-link]

Provides a rust interface for creating (`sgx_create_enclave_from_buffer_ex()`)
and persisting SGX enclaves.

Example usage:

```ignore,rust
let enclave = EnclaveBuilder::new(&mut enclave_bytes).create().unrwap()
let result = unsafe { ecall_foo(*enclave, arg1, arg2) };
```

Users are responsible for providing their own bindings to their ECALLs.

## Table of Contents

- [License](#license)
- [Build Instructions](#build-instructions)
- [Intel SGX SDK](#intel-sgx-sdk)
- [Features](#features)
- [References](#references)

## License

Look for the *LICENSE* file at the root of the repo for more information.

## Build Instructions

The workspace can be built with `cargo build` and tested with `cargo test`.
Either command will recognize the cargo `--release` flag to build with
optimizations.

The [Intel SGX SDK](#intel-sgx-sdk) needs to be installed.

## Intel SGX SDK

See <https://github.com/intel/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package>
for installation instructions.

The environment variable `SGX_SDK` can be used to specify where the SDK is
installed. When unset the location will default to `/opt/intel/sgxsdk`

## Features

When no features are present the SGX hardware libraries will be linked in. When
the `sim` feature is present the simulation SGX libraries will be linked in.

## References

- <https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_Enclave_Common_Loader_API_Reference.pdf>
- <https://github.com/intel/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package>

[chat-image]: https://img.shields.io/discord/844353360348971068?style=flat-square
[chat-link]: https://mobilecoin.chat
[license-image]: https://img.shields.io/crates/l/mc-sgx-urts?style=flat-square
[target-image]: https://img.shields.io/badge/target-x86__64-blue?style=flat-square
[crate-image]: https://img.shields.io/crates/v/mc-sgx-urts.svg?style=flat-square
[crate-link]: https://crates.io/crates/mc-sgx-urts
[docs-image]: https://img.shields.io/docsrs/mc-sgx-urts?style=flat-square
[docs-link]: https://docs.rs/crate/mc-sgx-urts
[deps-image]: https://deps.rs/crate/mc-sgx-urts/0.4.1/status.svg?style=flat-square
[deps-link]: https://deps.rs/crate/mc-sgx-urts/0.4.1
