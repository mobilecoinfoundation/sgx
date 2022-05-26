// Copyright (c) 2022 The MobileCoin Foundation
//! Provides rust wrappers for the SGX untrusted runtime system (uRTS) functionality

use mc_sgx_urts_sys::{
    sgx_create_enclave_from_buffer_ex, sgx_destroy_enclave, sgx_enclave_id_t, sgx_status_t,
};
pub use mc_sgx_urts_sys::{sgx_report_t, sgx_target_info_t};
use std::ops::Deref;
use std::{fmt, os::raw::c_int, ptr};

/// Returns the report from the provided [Enclave]
///
/// While there is an interface to get an enclave report from inside the
/// enclave, `sgx_create_report()`, there is no standard way to get the
/// report from the untrusted side.
///
/// The [EnclaveReportFn] allows the users of [Enclave]s a general interface
/// to redirect to the specific ecall that the enclave may use for providing
/// back the report.
///
/// # Errors
///
/// When there is an error this will usually be a [Error:SgxStatus()] due to an
/// error in the underlying SGX interface. It is up to the implementor to decide
/// what other errors if any will be returned.
///
/// # Arguments
/// - `Enclave` The enclave the report is being created for.
/// - `Option<&sgx_target_info_t>` The target info to use.  When this is `None`
///     it is intended for the implementation to pass `null` as the
///     `target_info` to
///     [`sgx_create_report()`](https://download.01.org/intel-sgx/sgx-linux/2.8/docs/Intel_SGX_Developer_Reference_Linux_2.8_Open_Source.pdf#%5B%7B%22num%22%3A281%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C94.5%2C179.25%2C0%5D).
type EnclaveReportFn = fn(&Enclave, Option<&sgx_target_info_t>) -> Result<sgx_report_t, Error>;

#[derive(Debug, PartialEq)]
pub enum Error {
    // An error provided from the SGX SDK
    SgxStatus(sgx_status_t),
    NoReportFunction,
}

/// Struct for interfacing with the SGX SDK.  This should be used directly in
/// sgx calls `ecall_some_function(*enclave, ...)`.
///
/// Avoid storing the de-referenced instance of the enclave.  The de-referenced
/// value of the enclave will result in failures to the SGX SDK after the
/// enclave is dropped.
pub struct Enclave {
    // The enclave ID, assigned by the SGX interface
    id: sgx_enclave_id_t,
    report_fn: Option<EnclaveReportFn>,
}

impl Enclave {
    //TODO should this be called "get_report"?  Named create to match the sgx interface?
    /// Return report for this enclave.
    ///
    /// # Arguments
    /// - `target_info` The target info to use in creating the report.
    ///     See [EnclaveReportFn]
    ///
    /// # Errors
    /// - `[Error::NoReportFunction]` when this instance was created without a
    ///     `[EnclaveReportFn]`, see [`EnclaveBuilder::report_fn()`] for setting
    ///     the function.
    /// - `[Error::SgxStatus]` when there is any error communicating to the
    ///     SGX SDK.
    pub fn create_report(
        &self,
        target_info: Option<&sgx_target_info_t>,
    ) -> Result<sgx_report_t, Error> {
        match self.report_fn {
            None => Err(Error::NoReportFunction),
            Some(report_fn) => report_fn(self, target_info),
        }
    }
}

impl fmt::Debug for Enclave {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "id: {}", self.id)
    }
}

/// Build an [Enclave] for use with SGX calls.
pub struct EnclaveBuilder {
    // The bytes for the enclave.
    bytes: Vec<u8>,
    // `true` if the enclave should be created in debug mode
    debug: bool,
    // The report function to populate the [Enclave] with.  Defaults to `None`.
    report_fn: Option<EnclaveReportFn>,
}

impl EnclaveBuilder {
    /// Returns an EnclaveBuilder for the provided signed enclave.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The bytes representing the enclave file.  This should be a
    ///     signed enclave.
    pub fn new(bytes: &[u8]) -> EnclaveBuilder {
        EnclaveBuilder {
            bytes: bytes.into(),
            debug: false,
            report_fn: None,
        }
    }

    /// Toggle debugging of the enclave on or off.  The default is off.
    ///
    /// # Arguments
    ///
    /// * `debug` - `true` to enable enclave debugging, `false` to disable it.
    #[must_use]
    pub fn debug(mut self, debug: bool) -> EnclaveBuilder {
        self.debug = debug;
        self
    }

    /// Report function to use for the built [Enclave].
    ///
    /// This will be used when calling [Enclave.report()]
    ///
    /// # Arguments
    ///
    /// * `report_fn` - The function to use for creating [Enclave] reports,
    ///     [Enclave::report()].  This is `None` by default.  Passing in will
    ///     prevent creating reports, [Error::NoReportFunction].
    #[must_use]
    pub fn report_fn(mut self, report_fn: Option<EnclaveReportFn>) -> EnclaveBuilder {
        self.report_fn = report_fn;
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
    pub fn create(mut self) -> Result<Enclave, Error> {
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
            sgx_status_t::SGX_SUCCESS => Ok(Enclave::new(enclave_id, self.report_fn)),
            error => Err(Error::SgxStatus(error)),
        }
    }
}

impl From<Vec<u8>> for EnclaveBuilder {
    fn from(bytes: Vec<u8>) -> EnclaveBuilder {
        EnclaveBuilder {
            bytes,
            debug: false,
            report_fn: None,
        }
    }
}

impl Enclave {
    fn new(id: sgx_enclave_id_t, report_fn: Option<EnclaveReportFn>) -> Enclave {
        Enclave { id, report_fn }
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
    use std::mem::MaybeUninit;
    use test_enclave::{ecall_add_2, ecall_create_report, ENCLAVE};

    #[test]
    fn fail_to_create_enclave_with_bogus_bytes() {
        let builder = EnclaveBuilder::new(b"garbage bytes");
        assert_eq!(
            builder.create().unwrap_err(),
            Error::SgxStatus(sgx_status_t::SGX_ERROR_INVALID_ENCLAVE)
        );
    }

    #[test]
    fn creating_enclave_succeeds() {
        let builder = EnclaveBuilder::new(ENCLAVE);
        assert!(builder.create().is_ok());
    }

    #[test]
    fn create_enclave_builder_from_vector() {
        let vector = ENCLAVE.to_vec();
        assert!(EnclaveBuilder::from(vector).create().is_ok());
    }

    #[test]
    fn calling_into_an_enclave_function_provides_valid_results() {
        // Note: the `debug()` was added to ensure proper builder behavior of
        // the `create()` method.  It could go away if another test has need
        // of similar behavior.
        let enclave = EnclaveBuilder::new(ENCLAVE).debug(true).create().unwrap();

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
        let builder = EnclaveBuilder::new(b"");
        assert_eq!(builder.debug as c_int, 0);
    }

    #[test]
    fn when_debug_flag_is_true_it_is_1() {
        let builder = EnclaveBuilder::new(b"").debug(true);
        assert_eq!(builder.debug as c_int, 1);
    }

    #[test]
    fn no_report_function_results_in_error() {
        let enclave = EnclaveBuilder::new(ENCLAVE).create().unwrap();
        let target_info = MaybeUninit::zeroed();
        let target_info = unsafe { target_info.assume_init() };
        assert_eq!(
            enclave.create_report(Some(target_info)).unwrap_err(),
            Error::NoReportFunction
        );
    }

    #[test]
    fn report_function_provides_report() {
        let enclave = EnclaveBuilder::new(ENCLAVE)
            .report_fn(Some(|enclave, target_info| {
                let report = MaybeUninit::zeroed();
                let mut report = unsafe { report.assume_init() };
                let mut retval: sgx_status_t = sgx_status_t::SGX_SUCCESS;
                let info = match target_info {
                    Some(info) => info,
                    None => ptr::null(),
                };
                let result =
                    unsafe { ecall_create_report(**enclave, &mut retval, info, &mut report) };
                match result {
                    sgx_status_t::SGX_SUCCESS => match retval {
                        sgx_status_t::SGX_SUCCESS => Ok(report),
                        x => Err(Error::SgxStatus(x)),
                    },
                    x => Err(Error::SgxStatus(x)),
                }
            }))
            .create()
            .unwrap();

        let target_info = MaybeUninit::zeroed();
        let target_info = unsafe { target_info.assume_init() };
        let report = enclave.create_report(Some(&target_info)).unwrap();

        // This test is focusing on ensuring that we can get the report
        // from `encalve.get_report()`.  While we could call
        // `ecall_create_report` directly and compare 2 reports, this would just
        // be a copy and paste of the `report_fn()` above not providing much.
        // Instead we focus on ensuring that the report is more than zero inited,
        // The `mac` provides a stable value to verify. It is very unlikely to
        // be 0 as time goes on.
        assert_ne!(report.mac, [0; 16]);
    }
}
