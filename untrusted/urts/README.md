# Untrusted SGX rust interface

Provides a rust interface for creating (`sgx_create_enclave_from_buffer_ex()`) and persisting SGX enclaves.

Example usage:
```rust
let enclave = EnclaveBuilder::new(&mut enclave_bytes).create().unrwap()
let result = unsafe { ecall_foo(*enclave, arg1, arg2) };
```

Users are responsible for providing their own bindings to their ECALLs. 

# Table of Contents

- [License](#license)
- [Build Instructions](#build-instructions)
- [Intel SGX SDK](#intel-sgx-sdk)
- [Features](#features)
- [Crates](#crates)
- [References](#references)

## License

Look for the *LICENSE* file at the root of the repo for more information.

## Build Instructions

The workspace can be built with `cargo build` and tested with `cargo test`. Either command will recognize the
cargo `--release` flag to build with optimizations.

The [Intel SGX SDK](#intel-sgx-sdk) needs to be installed.

## Intel SGX SDK

See https://github.com/intel/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package for installation
instructions. 

The environment variable `SGX_SDK` can be used to specify where the SDK is installed. When unset the location will
default to `/opt/intel/sgxsdk`

## Features

When no features are present the SGX software simulation libraries will be linked in. When the `hw` feature is
present the hardware SGX libraries will be linked in.

## References

* https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_Enclave_Common_Loader_API_Reference.pdf
* https://github.com/intel/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package 
