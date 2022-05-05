# Untrusted SGX rust bindings

Provides a rust interface for creating (`sgx_create_enclave()`) and persisting SGX enclaves.

Example usage:
```rust
let mut enclave = Enclave::new(enclave_file_name);
enclave.create();
let id = enclave.get_id().unwrap();

let result = unsafe { ecall_foo(*id, arg1, arg2) };
```

Users are responsible for providing their own bindings to their ECALLs. 

# Table of Contents

- [License](#license)
- [Build Instructions](#build-instructions)
- [Intel SGX SDK](#intel-sgx-sdk)
- [References](#references)

## License

Look for the *LICENSE* file at the root of the repo more information.

## Build Instructions

The workspace can be built with `cargo build` and tested with `cargo test`. Either command will recognize the
cargo `--release` flag to build with optimizations.

The [Intel SGX SDK](#intel-sgx-sdk) needs to be installed.

The environment variable `SGX_MODE` controls whether to build for SGX software simulation or hardware. The valid values
are `SW` and `HW` respectively.  When unset will default to software simulation.

## Intel SGX SDK

See https://github.com/intel/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package for installation
instructions. 

The environment variable `SGX_SDK` can be used to specify where the SDK is installed. When unset the location will
default to `/opt/intel/sgxsdk`

## References

* https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_Enclave_Common_Loader_API_Reference.pdf
* https://github.com/intel/linux-sgx#build-the-intelr-sgx-sdk-and-intelr-sgx-psw-package 
