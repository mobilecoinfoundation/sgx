# MobileCoin SGX: DCAP QuoteVerification Types

[![Project Chat][chat-image]][chat-link]<!--
-->![License][license-image]<!--
-->![Target][target-image]<!--
-->[![Crates.io][crate-image]][crate-link]<!--
-->[![Docs Status][docs-image]][docs-link]<!--
-->[![Dependency Status][deps-image]][deps-link]

Idiomatic rust wrappers for DCAP quote verification.

This crate provides rust type definitions to support verifying quotes for Intel SGX DCAP attestation.

If you're looking for using the Intel&reg; DCAP libraries you may be interested in:

- [DCAP Orientation Guide][dcap-orientation-guide]
- [DCAP Installation][dcap-installation]
- [DCAP Reference][dcap-reference]
- [DCAP Repo][dcap-repo]

## Minimum Supported Rust Version

Rust **1.62** or higher.

Minimum supported Rust version can be changed in the future, but it will be done with a minor version bump.

## SemVer Policy

- All on-by-default features of this library are covered by SemVer
- MSRV is considered exempt from SemVer as noted above

[chat-image]: https://img.shields.io/discord/844353360348971068?style=flat-square
[chat-link]: https://mobilecoin.chat
[license-image]: https://img.shields.io/crates/l/mc-sgx-dcap-quoteverify-types?style=flat-square
[target-image]: https://img.shields.io/badge/target-any-brightgreen?style=flat-square
[crate-image]: https://img.shields.io/crates/v/mc-sgx-dcap-quoteverify-types.svg?style=flat-square
[crate-link]: https://crates.io/crates/mc-sgx-dcap-quoteverify-types
[docs-image]: https://img.shields.io/docsrs/mc-sgx-dcap-quoteverify-types?style=flat-square
[docs-link]: https://docs.rs/crate/mc-sgx-dcap-quoteverify-types
[deps-image]: https://deps.rs/crate/mc-sgx-dcap-quoteverify-types/0.6.1/status.svg?style=flat-square
[deps-link]: https://deps.rs/crate/mc-sgx-dcap-quoteverify-types/0.6.1

[dcap-reference]: <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
[dcap-repo]: <https://github.com/intel/SGXDataCenterAttestationPrimitives>
[dcap-installation]: <https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html>
[dcap-orientation-guide]: <https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html>
