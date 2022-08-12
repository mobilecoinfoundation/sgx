# MobileCoin's FFI Bindings to the Trusted runtime system(tRTS) SGX functionality

[![mc-sgx-trts-sys][crate-image]][crate-link]
![License][license-image]
[![Project Chat][chat-image]][chat-link]

[![Docs Status][docs-image]][docs-link]
[![CodeCov Status][codecov-image]][codecov-link]
[![dependency status][deps-image]][deps-link]

Provides the rust function bindngs to the `sgx_trts` library.

## Table of Contents

- [License](#license)
- [Build Instructions](#build-instructions)
- [Intel SGX SDK](#intel-sgx-sdk)
- [Features](#features)
- [References](#references)

## License

Look for the *LICENSE* file at the root of the repo for more information.

## Build Instructions

The workspace can be built with `cargo build`
> Due to the need to link to an enclave, tests are not currently supported.

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

[crate-image]: https://img.shields.io/crates/v/mc-sgx-trts-sys.svg?style=for-the-badge
[crate-link]: https://crates.io/crates/mc-sgx-trts-sys
[license-image]: https://img.shields.io/crates/l/mc-sgx-trts-sys?style=for-the-badge
[chat-image]: https://img.shields.io/discord/MOBILECOIN?style=for-the-badge
[chat-link]: https://mobilecoin.chat
[docs-image]: https://img.shields.io/docsrs/mc-sgx-trts-sys?style=for-the-badge
[docs-link]: https://docs.rs/crate/mc-sgx-trts-sys
[codecov-image]: https://img.shields.io/codecov/c/github/mobilecoinfoundation/sgx/develop?style=for-the-badge
[codecov-link]: https://codecov.io/gh/mobilecoinfoundation/sgx
[deps-image]: https://deps.rs/crate/mc-sgx-trts-sys/status.svg?style=for-the-badge
[deps-link]: https://deps.rs/crate/mc-sgx-trts-sys
