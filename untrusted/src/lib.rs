// Copyright (c) 2022 The MobileCoin Foundation
// See https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_Enclave_Common_Loader_API_Reference.pdf
//
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::{ffi::CString, mem::MaybeUninit, os::raw::c_int};
use std::ops::Deref;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[derive(PartialEq, Debug)]
pub enum Error {
    SgxStatus(sgx_status_t),
}

/// Struct for interfacing with the SGX SDK.  This should be used directly in
/// sgx calls `sgx_create_enclave(*enclave, ...)`.
///
/// Avoid storing the de-referenced instance of the enclave.  The de-referenced
/// value of the enclave will result in failures to the SGX SDK after the
/// enclave is dropped.
#[derive(Debug, PartialEq)]
pub struct Enclave {
    // The enclave ID, assigned by the sgx interface
    id: sgx_enclave_id_t,
}

#[derive(Default)]
pub struct EnclaveBuilder {
    // The filename of the enclave
    filename: CString,

    // `true` if the enclave should be created in debug mode
    debug: bool,
}

impl EnclaveBuilder {
    /// Returns an EnclaveBuilder for the provided signed enclave.
    ///
    /// # Arguments
    ///
    /// * `filename` - The name of the enclave file.  This should be a signed
    ///     enclave.
    pub fn new(filename: &str) -> EnclaveBuilder {
        let filename = CString::new(filename).expect("Can't convert enclave filename to CString.");
        EnclaveBuilder {
            filename,
            ..Default::default()
        }
    }

    /// Toggle debugging of the enclave on or off.  The default is off.
    ///
    /// # Arguments
    ///
    /// * `debug` - `true` to enable enclave debugging, `false` to disable it.
    pub fn debug(&mut self, debug: bool) -> &mut EnclaveBuilder {
        self.debug = debug;
        self
    }

    /// Create the enclave
    ///
    /// Will talk to the SGX SDK to create the enclave.  Once the enclave has
    /// been created then calls into the enclave can be made by de-referencing
    /// the enclave.
    ///
    /// See
    /// <https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_Enclave_Common_Loader_API_Reference.pdf>
    /// for error codes and their meaning.
    pub fn create(self) -> Result<Enclave, Error> {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: c_int = 0;
        let mut misc_attr: sgx_misc_attribute_t =
            unsafe { MaybeUninit::<sgx_misc_attribute_t>::zeroed().assume_init() };
        let mut enclave_id: sgx_enclave_id_t = 0;
        let result = unsafe {
            sgx_create_enclave(
                self.filename.as_ptr(),
                self.debug as c_int,
                &mut launch_token as *mut sgx_launch_token_t,
                &mut launch_token_updated,
                &mut enclave_id,
                &mut misc_attr,
            )
        };
        match result {
            _status_t_SGX_SUCCESS => Ok(Enclave { id: enclave_id }),
            error => Err(Error::SgxStatus(error)),
        }
    }
}

impl Deref for Enclave {
    type Target = sgx_enclave_id_t;
    fn deref(&self) -> &Self::Target {
        &self.id
    }
}

impl Drop for Enclave {
    /// Destroys the enclave through the SGX interface.
    /// Any de-referenced value from [Enclave] is not valid after
    /// dropping.
    fn drop(&mut self) {
        // Per the docs, this will only return SGX_SUCCESS or
        // SGX_ERROR_INVALID_ENCLAVE_ID. The invalid ID error will only
        // happen when the ID is invalid, the enclave hasn't been loaded,
        // or the enclave has already been destroyed. Any of these cases
        // don't afford corrective action, so ignore the return value
        unsafe { sgx_destroy_enclave(self.id) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_enclave::{ecall_add_2, ENCLAVE_PATH};

    #[test]
    fn fail_to_create_enclave_with_non_existent_file() {
        let builder = EnclaveBuilder::new("does_not_exist.signed.so");
        assert_eq!(
            builder.create(),
            Err(Error::SgxStatus(_status_t_SGX_ERROR_ENCLAVE_FILE_ACCESS))
        );
    }

    #[test]
    fn creating_enclave_succeeds() {
        let builder = EnclaveBuilder::new(ENCLAVE_PATH);
        assert!(builder.create().is_ok());
    }

    #[test]
    fn calling_into_a_an_enclave_function_provides_valid_results() {
        let enclave = EnclaveBuilder::new(ENCLAVE_PATH).create().unwrap();

        let mut sum: c_int = 3;
        let result = unsafe { ecall_add_2(*enclave, 3, &mut sum) };
        assert_eq!(result, _status_t_SGX_SUCCESS);
        assert_eq!(sum, 3 + 2);
    }

    #[test]
    fn default_debug_flag_is_0() {
        // For the debug flag it's not easy, in a unit test, to test it was
        // passed to `sgx_create_enclave()`, instead we focus on the
        // `as c_int` portion maps correctly to 0 or 1
        let builder = EnclaveBuilder::new("");
        assert_eq!(builder.debug as c_int, 0);
    }

    #[test]
    fn when_debug_flag_is_true_it_is_1() {
        let mut builder = EnclaveBuilder::new("");
        builder.debug(true);
        assert_eq!(builder.debug as c_int, 1);
    }
}
