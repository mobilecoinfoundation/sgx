# MobileCoin's FFI Bindings to the untrusted SGX functionality

[![mc-sgx-urts-sys][crate-image]][crate-link]
![License][license-image]
[![Project Chat][chat-image]][chat-link]

[![Docs Status][docs-image]][docs-link]
[![CodeCov Status][codecov-image]][codecov-link]
[![dependency status][deps-image]][deps-link]

Provides the rust function bindings to the `sgx_urts` library.

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

[crate-image]: https://img.shields.io/crates/v/mc-sgx-urts-sys.svg?style=for-the-badge
[crate-link]: https://crates.io/crates/aead
[license-image]: https://img.shields.io/crates/l/mc-sgx-urts-sys?style=for-the-badge
[chat-image]: https://img.shields.io/discord/MOBILECOIN?style=for-the-badge
[chat-link]: https://mobilecoin.chat
[docs-image]: https://img.shields.io/docsrs/mc-sgx-urts-sys?style=for-the-badge
[docs-link]: https://docs.rs/crate/mc-sgx-urts-sys
[codecov-image]: https://img.shields.io/codecov/c/github/mobilecoinfoundation/sgx/develop?style=for-the-badge
[codecov-link]: https://codecov.io/gh/mobilecoinfoundation/sgx
[deps-image]: https://deps.rs/crate/mc-sgx-urts-sys/status.svg?style=for-the-badge
[deps-link]: https://deps.rs/crate/mc-sgx-urts-sys
