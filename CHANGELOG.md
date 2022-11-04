# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

### Added

- `verify_nonce()`: `mc_sgx_dcap_types::Quote3` can verify a nonce matches that
  which was provided in a `mc_sgx_core_types::ReportData`.

### Changed

- `mc_sgx_dcap_types::Quote3Error` was renamed to `mc_sgx_dcap_types::SgxError`
  to better indicate it's an error coming from the SGX SDK, not specific to
  interacting with a Quote3.

## [0.3.0] - 2022-10-20

### Changed

- Add `mc_sgx_tservice::SealError`, make `SealedBuilder` use it instead of
  `mc_sgx_core_types::Error`.
- `mc-sgx-dcap-ql::set_path` and `mc-sgx-dcap-ql::load_policy` have been
  replaced with `mc-sgx-dcap-ql::PathInitializer` and
  `mc-sgx-dcap-ql::LoadPolicyInitializer`
- `mc-sgx-dcap-quoteverify::set_path` and
  `mc-sgx-dcap-quoteverify::load_policy` have been replaced
  with `mc-sgx-dcap-quoteverify::PathInitializer` and
  `mc-sgx-dcap-quoteverify::LoadPolicyInitializer`
  
## [0.2.1] - 2022-10-14

### Added

- `mc-sgx-urts`: Idiomatic Rust Types for the `sgx_urts` library

### Fixed

doc builds for:
    - `mc-sgx-dcap-ql-sys`
    - `mc-sgx-dcap-quoteverify`
    - `mc-sgx-dcap-quoteverify-sys`
    - `mc-sgx-dcap-quoteverify-sys-types`
    - `mc-sgx-dcap-quoteverify-types`
    - `mc-sgx-dcap-sys-types`
    - `mc-sgx-dcap-tvl-sys`
    - `mc-sgx-dcap-types`

## [0.2.0] - 2022-10-07

### Added

- `mc-sgx-core-types`: Idiomatic Rust Types for SGX primitives
- `mc-sgx-core-types`: Idiomatic Rust for SGX primitives
- `mc-sgx-capable`: Idiomatic Rust bindings for the `sgx_capable` library
- `mc-sgx-capable-types`: Idiomatic Rust types for the `sgx_capable` library
- `mc-sgx-dcap-ql`: Idiomatic Rust bindings for the `sgx_dcap_ql` library
- `mc-sgx-dcap-ql-types`: Idiomatic Rust types for the `sgx_dcap_ql` library
- `mc-sgx-dcap-quoteverify`: Idiomatic Rust bindings for the `sgx_dcapquoteverify` library
- `mc-sgx-dcap-quoteverify-types`: Idiomatic Rust types for the `sgx_dcapquoteverify` library
- `mc-sgx-trts`: Idiomatic Rust bindings for the `sgx_trts` library
- `mc-sgx-tservice`: Idiomatic Rust bindings for the `sgx_tservice` library
- `mc-sgx-tservice-types`: Idiomatic Rust Types for the `sgx_tservice` library

### Changed

- Update all `README.md` files.

## [0.1.0] - 2022-08-18

- Initial release of FFI bindings crates

<!-- next-url -->
[Unreleased]: https://github.com/mobilecoinfoundation/sgx/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/mobilecoinfoundation/sgx/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.1.0
