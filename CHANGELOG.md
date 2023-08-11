# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- next-header -->

## [Unreleased] - ReleaseDate

## [0.7.4] - 2023-08-08

### Fixed

- Fixed `tcb` feature in `mc-sgx-dcap-types` missing dependency on `serde/alloc`
- Fixed vendored include paths for the `*-sys-*` crate builds. In particular
  build issues related to `time.h`.

## [0.7.3] - 2023-08-07

### Added

- Added `Deserialize` and `Serialize` traits to:
  - `mc-sgx-dcap-types::Collateral`
  - `mc-sgx-dcap-types::Quote3Error`
  - `mc-sgx-dcap-types::Quote3<Vec<u8>>`

### Removed

- Removed patch version restriction on `serde` crate dependency.

## [0.7.2] - 2023-07-20

### Added

- Added `Deserialize` and `Serialize` traits to:
  - `mc-sgx-core-types::TargetInfo`
  - `mc-sgx-core-types::Report`
  - `mc-sgx-dcap-types::Quote3`

## [0.7.1] - 2023-07-12

### Added

- Added `FromHex` implementation for MrEnclave and MrSigner
- Added `From<Quote3<&[u8]>> for Quote3<Vec<u8>>`

### Fixed

- Fixed `ExtendedFeatureRequestMask::AMX`
  - Previously the `ExtendedFeatureRequestMask::AMX` was mapped to `SGX_XFRM_LEGACY`. Now `ExtendedFeatureRequestMask::AMX` correctly maps to `SGX_XFRM_AMX`.

## [0.7.0] - 2023-06-22

### Added

- Added the `mc-sgx-dcap-type::Collateral` type. This can be retrieved via the
  `mc-sgx-dcap-quoteverify::Collateral` trait on a `mc-sgx-dcap_types::Quote3`.
- Added the `BitAnd` trait implementation for `mc-sgx-core-types::MiscellaneousSelect`.
- Added the `BitAnd` trait implementation for `mc-sgx-core-types::Attributes`.
- Added the ability to get the QE(Quoting Enclave) report body from
  `mc-sgx-dcap-types::SignatureData`.
  
### Changed

- `mc-sgx-core-types::Attributes::set_flags()` and
  `mc-sgx-core-types::Attributes::set_extended_features_mask()` have been
  updated to take dedicated types `mc-sgx-core-types::AttributesFlags` and
  `mc-sgx-core-types::ExtendedFeaturesMask` respectively.
- `serde` is no longer an optional dependency behind a `serde` feature. It is
  now a required dependency.
- The SGX SDK version is now 2.19.100.3
- The `MrSigner` and `MrEnclave` `Display` implementations has been changed.
  Previously they were displayed as `0xABCD_EF01_2345_6789_...` now they are
  displayed as `abcdef0123456789...`. This is to make it easier to copy the
  value into code sources or command line utilities.

## [0.6.1] - 2023-05-23

### Added

- Added `mc-sgx-dcap-types::TCBInfo` which provides the TCB (Trusted Compute Base)
  for a quoted enclave.
- Added a method, `mc-sgx-dcap-types::Quote3::verify()`, to verify the signature
  of a quoted enclave.

## [0.6.0] - 2023-04-12

### Added

- Implemented `Display` for `mc-sgx-core-types` structs.

### Changed

- Upgraded to `bitflags` to 2.0. This caused API changes in `KeyPolicy` methods and trait derivations. See bitflags 2.0 [changelog](https://github.com/bitflags/bitflags/blob/main/CHANGELOG.md) for more information.

## [0.5.0] - 2023-03-08

### Added

- `BitAnd` implementation for `mc_sgx_core_types::ReportData`.
- `Copy` trait to:
  - `mc_sgx_core_types::MiscellaneousSelect`
  - `mc_sgx_core_types::IsvProductId`
  - `mc_sgx_core_types::ConfigSvn`
  - `mc_sgx_core_types::IsvSvn`

### Changed

- `mc_sgx_core_types::ReportBody::mr_enclave()` now returns a `MrEnclave`
  instead of a `Measurement`.
- `mc_sgx_core_types::ReportBody::mr_signer()` now returns a `MrSigner`
  instead of a `Measurement`.
- `mc_sgx_core_types::TargetInfo::mr_enclave()` now returns a `MrEnclave`
  instead of a `Measurement`.

### Removed

- `mc_sgx_core_types::Measurement` has been removed. Use `MrEnclave` or
  `MrSigner` instead.
- Copy trait from `mc_sgx_core_types::MrEnclave` and
  `mc_sgx_core_types::MrSigner`

## [0.4.2] - 2023-02-10

### Added

- Build script wrapper for SGX sign utility.

## [0.4.1] - 2023-01-30

### Added

- Synchronization constants and defaults to `mc-sgx-tstdc-sys-types`.
- `mc-sgx-tstdc` crate with rust wrappers providing low-level constructs
  around synchronization primitives. `mc-sgx-sync` should be used for the
  higher-level constructs that mimic `std::sync`.
- `mc-sgx-sdk-tools` crate which provides rust wrappers around enclave building
  utilities.

## [0.4.0] - 2022-12-14

### Added

- `SignatureData`: `mc_sgx_dcap_types::SignatureData` wraps up
  the `sgx_ql_ecdsa_sig_data_t` type.
- `verify_nonce()`: `mc_sgx_dcap_types::Quote3` can verify a nonce matches that
  which was provided in a `mc_sgx_core_types::ReportData`.

### Changed

- `mc_sgx_dcap_types::Quote3Error` was renamed to `mc_sgx_dcap_types::QlError`
  to better indicate it's an error coming from the SGX quote library SDK.

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
[Unreleased]: https://github.com/mobilecoinfoundation/sgx/compare/v0.7.4...HEAD
[0.7.4]: https://github.com/mobilecoinfoundation/sgx/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/mobilecoinfoundation/sgx/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/mobilecoinfoundation/sgx/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/mobilecoinfoundation/sgx/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.6.1...v0.7.0
[0.6.1]: https://github.com/mobilecoinfoundation/sgx/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/mobilecoinfoundation/sgx/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/mobilecoinfoundation/sgx/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/mobilecoinfoundation/sgx/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mobilecoinfoundation/sgx/compare/v0.1.0
