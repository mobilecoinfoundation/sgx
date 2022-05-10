// Copyright (c) 2022 The MobileCoin Foundation

#![allow(non_upper_case_globals)]

use mc_sgx_urts_sys::{
    sgx_create_enclave_from_buffer_ex, sgx_destroy_enclave, sgx_enclave_id_t, sgx_status_t,
};
use std::ops::Deref;
use std::{os::raw::c_int, ptr};

#[derive(PartialEq, Debug)]
pub enum Error {
    SgxStatus(sgx_status_t),
}

/// Struct for interfacing with the SGX SDK.  This should be used directly in
/// sgx calls `ecall_some_function(*enclave, ...)`.
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
pub struct EnclaveBuilder<'a> {
    // The bytes for the enclave.
    //
    // This needs to be mutable per the signature of
    // `sgx_create_enclave_from_buffer_ex()`.  See comment in
    // [EnclaveBuilder::create()] for more info.
    bytes: &'a mut [u8],

    // `true` if the enclave should be created in debug mode
    debug: bool,
}

impl<'a> EnclaveBuilder<'a> {
    /// Returns an EnclaveBuilder for the provided signed enclave.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The bytes representing the enclave file.  This should be a
    ///     signed enclave.  This needs to be mutable as the sgx interface will
    ///     modify the bytes in [EnclaveBuilder::create()].  The `bytes` will
    ///     not be usable to create another enclave after calling
    ///     [EnclaveBuilder::create()].  If more than one enclave is needed from
    ///     the same original `bytes` be sure and copy them to each builder,
    ///     prior to calling [EncalveBuilder::create()].
    pub fn new(bytes: &mut [u8]) -> EnclaveBuilder {
        EnclaveBuilder {
            bytes,
            ..Default::default()
        }
    }

    /// Toggle debugging of the enclave on or off.  The default is off.
    ///
    /// # Arguments
    ///
    /// * `debug` - `true` to enable enclave debugging, `false` to disable it.
    pub fn debug(&mut self, debug: bool) -> &'a mut EnclaveBuilder {
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
    pub fn create(&mut self) -> Result<Enclave, Error> {
        let mut enclave_id: sgx_enclave_id_t = 0;
        let result = unsafe {
            // Per the API reference `buffer` is an input, however the signature
            // lacks the const qualifier.  Through testing it has been shown
            // that `sgx_create_enclave_from_buffer_ex()` *will* modify the
            // `buffer` parameter.  This can be seen by copying the input bytes
            // and comparing before and after.
            //
            //      let mut buffer = self.bytes.to_vec();
            //      println!("Pre comparing {}", buffer.as_slice() == self.bytes);
            //      let result = unsafe {sgx_create_enclave_from_buffer_ex(...)};
            //      println!("Post comparing {}", buffer.as_slice() == self.bytes);
            //
            // The modification that `sgx_create_enclave_from_buffer_ex()`
            // makes to the `buffer` is such that if one were to re-use the
            // modified buffer in another call to
            // `sgx_create_enclave_from_buffer_ex()` then
            // `SGX_ERROR_INVALID_ENCLAVE_ID` would be returned.
            sgx_create_enclave_from_buffer_ex(
                self.bytes.as_mut_ptr(),
                self.bytes.len().try_into().unwrap(),
                self.debug as c_int,
                &mut enclave_id,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        match result {
            sgx_status_t::SGX_SUCCESS => Ok(Enclave::new(enclave_id)),
            error => Err(Error::SgxStatus(error)),
        }
    }
}

impl Enclave {
    fn new(id: sgx_enclave_id_t) -> Enclave {
        Enclave { id }
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
    use test_enclave::{ecall_add_2, ENCLAVE};

    #[test]
    fn fail_to_create_enclave_with_non_existent_file() {
        let mut bytes = b"garbage bytes".to_vec();
        let mut builder = EnclaveBuilder::new(&mut bytes);
        assert_eq!(
            builder.create(),
            Err(Error::SgxStatus(sgx_status_t::SGX_ERROR_INVALID_ENCLAVE))
        );
    }

    #[test]
    fn creating_enclave_succeeds() {
        let mut bytes = ENCLAVE.to_vec();
        let mut builder = EnclaveBuilder::new(&mut bytes);
        assert!(builder.create().is_ok());
    }

    #[test]
    fn calling_into_a_an_enclave_function_provides_valid_results() {
        let mut bytes = ENCLAVE.to_vec();

        // Note: the `debug()` was added to ensure proper builder behavior of
        // the `create()` method.  It could go away if another test has need
        // of similar behavior.
        let enclave = EnclaveBuilder::new(&mut bytes)
            .debug(true)
            .create()
            .unwrap();

        let mut sum: c_int = 3;
        let result = unsafe { ecall_add_2(*enclave, 3, &mut sum) };
        assert_eq!(result, sgx_status_t::SGX_SUCCESS);
        assert_eq!(sum, 3 + 2);
    }

    #[test]
    fn default_debug_flag_is_0() {
        // For the debug flag it's not easy, in a unit test, to test it was
        // passed to `sgx_create_enclave()`, instead we focus on the
        // `as c_int` portion maps correctly to 0 or 1
        let mut bytes = b"".to_vec();
        let builder = EnclaveBuilder::new(&mut bytes);
        assert_eq!(builder.debug as c_int, 0);
    }

    #[test]
    fn when_debug_flag_is_true_it_is_1() {
        let mut bytes = b"".to_vec();
        let mut builder = EnclaveBuilder::new(&mut bytes);
        let builder = builder.debug(true);
        assert_eq!(builder.debug as c_int, 1);
    }
}
