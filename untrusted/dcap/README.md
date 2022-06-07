# Rust interface for Intel SGX DCAP(Data Center Attestation Primitives).

This crate provides functionality for generating and verifying DCAP quotes.  
Each piece of the functionality, generate and verify, is behind a feature.
This allows code to only generate a quote, or for code to only verify received 
quotes.

Example usage:
```rust
let quote = Quote::generate(enclave).unrwap();
let result = quote.verify();
```

# Table of Contents

- [License](#license)
- [Build Instructions](#build-instructions)
- [Intel SGX DCAP Install](#intel-sgx-sdk)
- [Features](#features)
- [References](#references)

## License

Look for the *LICENSE* file at the root of the repo for more information.

## Build Instructions

The workspace can be built with `cargo build` and tested with 
`cargo test --features-all`. Either command will recognize the cargo 
`--release` flag to build with optimizations.

The [Intel SGX SDK](#intel-sgx-sdk) needs to be installed.

## Intel SGX SDK

See https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf
for installation instructions.

## Features

There are two features available to this package: `generate` and `verify`.  
Like most rust features these are additive and both can be used if needed.

### `generate`

The generate feature provides functionality to generate quotes for enclaves.
```rust
use mc_sgx_dcap::{Generate, Quote};

let quote = Quote::generate(enclave).unrwap();

// Do something with the quote
```

### `verify`

The `verify` feature provides functionality for verifying quotes. These quotes can be generated in process or they can
come from some other process.
```rust
use mc_sgx_dcap::{Quote, Verify};
let quote = Quote{some_quote_data};
let result = quote.verify();
```

## References

* https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf
* https://www.intel.com/content/www/us/en/developer/articles/technical/quote-verification-attestation-with-intel-sgx-dcap.html 
