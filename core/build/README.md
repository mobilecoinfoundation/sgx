# MobileCoin SGX: Build Utilities

[![Project Chat][chat-image]][chat-link]<!--
-->![License][license-image]<!--
-->![Target][target-image]<!--
-->[![Crates.io][crate-image]][crate-link]<!--
-->[![Docs Status][docs-image]][docs-link]<!--
-->[![Dependency Status][deps-image]][deps-link]

Utilities for compiling FFI wrappers to SGX libraries.

## Native Dependencies and Vendored Headers

CI and the devcontainer use SGX SDK **2.30.101.1** (release **2.30.1**) and
DCAP **1.27.101.1** (release **1.27.1**). Use these versions for native builds
and tests so the generated FFI layouts match the linked libraries, especially
the quote verification supplemental-data structure.

The `headers/` directory contains unmodified headers from:

- The [SGX SDK 2.30.1 installer][sdk-installer]: its top-level headers and
  trusted libc headers under `include/tlibc/`.
- Intel's [Ubuntu APT repository][sgx-apt]: `libsgx-headers` 2.30.101.1 and
  `libsgx-dcap-ql-dev` / `libsgx-dcap-quote-verify-dev` 1.27.101.1, using the
  `noble1` package builds.

Headers are always read from this vendored directory when generating bindings.
An SGX SDK installation is needed for native SDK libraries and tools; DCAP
runtime and development libraries must also be available to the native linker.

## Environment Variables

Below are environment variables that affect the building of the SGX FFI
wrappers.

- `SGX_SDK` The path to the Intel SGX SDK libraries and tools. Defaults to
  `/opt/intel/sgxsdk` when unset. This does not change the vendored include paths.

- `CFLAGS` - Used when generating the rust bindings. Useful to specify
  system include paths. Multiple arguments can be separated with whitespace.
  This does **not** support escaped whitespace as specified in
  <https://pubs.opengroup.org/onlinepubs/9699919799/utilities/V3_chap02.html>

[sdk-installer]: https://download.01.org/intel-sgx/sgx-linux/2.30.1/distro/ubuntu24.04-server/sgx_linux_x64_sdk_2.30.101.1.bin
[sgx-apt]: https://download.01.org/intel-sgx/sgx_repo/ubuntu/
[crate-image]: https://img.shields.io/crates/v/mc-sgx-core-build.svg?style=flat-square
[crate-link]: https://crates.io/crates/mc-sgx-core-build
[license-image]: https://img.shields.io/crates/l/mc-sgx-core-build?style=flat-square
[target-image]: https://img.shields.io/badge/target-any-brightgreen?style=flat-square
[chat-image]: https://img.shields.io/discord/844353360348971068?style=flat-square
[chat-link]: https://mobilecoin.chat
[docs-image]: https://img.shields.io/docsrs/mc-sgx-core-build?style=flat-square
[docs-link]: https://docs.rs/crate/mc-sgx-core-build
[deps-image]: https://deps.rs/crate/mc-sgx-core-build/0.13.0/status.svg?style=flat-square
[deps-link]: https://deps.rs/crate/mc-sgx-core-build/0.13.0
