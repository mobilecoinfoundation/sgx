// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]

use mc_sgx_core_types::Error;
use mc_sgx_core_sys_types::{sgx_status_t, sgx_target_info_t};
use mc_sgx_urts_sys::{sgx_create_enclave_from_buffer_ex, sgx_destroy_enclave, sgx_get_target_info,
SGX_CREATE_ENCLAVE_EX_PCL, SGX_CREATE_ENCLAVE_EX_KSS, SGX_CREATE_ENCLAVE_EX_PCL_BIT_IDX, SGX_CREATE_ENCLAVE_EX_KSS_BIT_IDX};
use mc_sgx_urts_sys_types::{sgx_enclave_id_t, sgx_kss_config_t};
use std::{mem::MaybeUninit, os::raw::c_int, ptr, io::Read, fs::File, path::Path, ffi::c_void};

/// Struct for interfacing with the SGX SDK.  This should be used in
/// sgx calls as `ecall_some_function(*enclave.get_id(), ...)`.
///
/// Avoid storing the de-referenced ID of the enclave.  The de-referenced
/// ID of the enclave will result in failures to the SGX SDK after the
/// enclave is dropped.
#[derive(Debug, PartialEq, Eq)]
pub struct Enclave {
    // The enclave ID, assigned by the SGX interface
    id: sgx_enclave_id_t,
}

/// Build an [Enclave] for use with SGX calls.
pub struct EnclaveBuilder {
    // The bytes for the enclave.
    bytes: Vec<u8>,

    // `true` if the enclave should be created in debug mode
    debug: bool,
}

impl EnclaveBuilder {
    /// Returns an EnclaveBuilder for the provided signed enclave.
    ///
    /// # Arguments
    ///
    /// * `path` - The path to the enclave file. This should be a signed
    ///   enclave.
    pub fn new(path: impl AsRef<Path>) -> std::io::Result<EnclaveBuilder> {
        let file = File::open(path)?;
        file.try_into()
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

    /// Create the enclave
    ///
    /// Will talk to the SGX SDK to create the enclave.  Once the enclave has
    /// been created then calls into the enclave can be made using the enclave ID.
    pub fn create(mut self) -> Result<Enclave, Error> {
        let mut enclave_id: sgx_enclave_id_t = 0;
        let mut ex_features = 0;
        let mut ex_features_p :[*const c_void; 32] = [ptr::null(); 32];
        
        if let Some(pcl_key) = self.pcl_key {
            eprintln!("yep sgx enabled");
            ex_features |= SGX_CREATE_ENCLAVE_EX_PCL;
            ex_features_p[SGX_CREATE_ENCLAVE_EX_PCL_BIT_IDX as usize] = pcl_key.as_ptr() as *const c_void;
        }
        
        if let Some(kss_config) = self.kss_config {
            ex_features |= SGX_CREATE_ENCLAVE_EX_KSS;
            ex_features_p[SGX_CREATE_ENCLAVE_EX_KSS_BIT_IDX as usize] = &kss_config as *const sgx_kss_config_t as *const c_void;
        }
        
        let result = 
                unsafe {
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
                        self.bytes.len(),
                        self.debug as c_int,
                        &mut enclave_id,
                        ptr::null_mut(),
                        ex_features,
                        &mut ex_features_p as *mut *const c_void,
                    )
                };

        match result {
            sgx_status_t::SGX_SUCCESS => Ok(Enclave { id: enclave_id }),
            error => {
                eprintln!("error {:?}", error);
                Err(error.into())
            },
        }
    }
}

impl From<Vec<u8>> for EnclaveBuilder {
    fn from(input: Vec<u8>) -> EnclaveBuilder {
        EnclaveBuilder {
            bytes: input,
            debug: false,
            pcl_key: None,
            kss_config: None,
        }
    }
}

impl From<&[u8]> for EnclaveBuilder {
    fn from(input: &[u8]) -> EnclaveBuilder {
        EnclaveBuilder {
            bytes: input.to_vec(),
            debug: false,
            pcl_key: None,
            kss_config: None,
        }
    }
}

impl<const N: usize> From<&[u8; N]> for EnclaveBuilder {
    fn from(input: &[u8; N]) -> EnclaveBuilder {
        EnclaveBuilder {
            bytes: input.to_vec(),
            debug: false,
            pcl_key: None,
            kss_config: None,
        }
    }
}

impl TryFrom<File> for EnclaveBuilder {
    type Error = std::io::Error;
    fn try_from(mut input: File) -> std::io::Result<EnclaveBuilder> {
        let mut bytes = vec![];
        input.read_to_end(&mut bytes)?;
        Ok(EnclaveBuilder {
            bytes,
            debug: false,
            pcl_key: None,
            kss_config: None,
        })
    }
}

impl Enclave {
    /// Returns the target info for the enclave.
    pub fn get_target_info(&self) -> Result<sgx_target_info_t, Error> {
        let mut target_info = MaybeUninit::uninit();
        let result = unsafe {
            sgx_get_target_info(self.id, target_info.as_mut_ptr())
        };
        match result {
            sgx_status_t::SGX_SUCCESS => Ok(unsafe { target_info.assume_init() }),
            error => Err(error.into()),
        }
    }

    /// Returns a reference to the enclave ID.
    /// Returns by reference because enclave ID will not be valid after the enclave is dropped.
    pub fn get_id(&self) -> &sgx_enclave_id_t {
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
    use std::io::{Write, Seek};
    use test_enclave::{ecall_add_2, ENCLAVE, ENCLAVE_KSS, ENCLAVE_PCL, ENCLAVE_PCL_KEY};
    use tempfile::{tempfile, NamedTempFile};

    #[test]
    fn fail_to_create_enclave_with_bogus_bytes() {
        let builder = EnclaveBuilder::from(b"garbage bytes");
        assert_eq!(
            builder.create(),
            Err(sgx_status_t::SGX_ERROR_INVALID_ENCLAVE.into())
        );
    }

    #[test]
    fn creating_enclave_succeeds() {
        let builder = EnclaveBuilder::from(ENCLAVE);
        assert!(builder.create().is_ok());
    }

    #[test]
    fn creating_plaintext_enclave_fails_with_pcl() {
        let builder = EnclaveBuilder::from(ENCLAVE).pcl(b"some garbage".to_vec());
        assert_eq!(
            builder.create(),
            Err(sgx_status_t::SGX_ERROR_PCL_NOT_ENCRYPTED.into())
        );
    }

    #[test]
    fn creating_enclave_with_kss_fails_when_not_enabled() {
        let builder = EnclaveBuilder::from(ENCLAVE).kss(sgx_kss_config_t::default());
        assert_eq!(
            builder.create(),
            Err(sgx_status_t::SGX_ERROR_FEATURE_NOT_SUPPORTED.into())
        );
    }

    #[test]
    fn creating_enclave_with_kss_succeeds_when_enabled() {
        let builder = EnclaveBuilder::from(ENCLAVE_KSS).kss(sgx_kss_config_t::default());
        assert!(builder.create().is_ok());
    }

    #[test]
    fn creating_enclave_with_pcl_succeeds_when_enabled_with_correct_key() {
        let builder = EnclaveBuilder::from(ENCLAVE_PCL).pcl(ENCLAVE_PCL_KEY.to_vec());
        let result = builder.create();
        eprintln!("{:?}", result);
        assert!(result.is_ok());
    }

    #[test]
    fn create_enclave_builder_from_vector() {
        let vector = ENCLAVE.to_vec();
        assert!(EnclaveBuilder::from(vector).create().is_ok());
    }

    #[test]
    fn create_enclave_builder_from_file() {
        let mut file = tempfile().unwrap();
        file.write_all(ENCLAVE).unwrap();
        file.rewind().unwrap();
        assert!(EnclaveBuilder::try_from(file).unwrap().create().is_ok());
    }

    #[test]
    fn create_enclave_builder_from_file_path() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(ENCLAVE).unwrap();
        file.rewind().unwrap();
        let path = file.path();
        assert!(EnclaveBuilder::new(path).unwrap().create().is_ok());
    }

    #[test]
    fn calling_into_an_enclave_function_provides_valid_results() {
        // Note: the `debug()` was added to ensure proper builder behavior of
        // the `create()` method.  It could go away if another test has need
        // of similar behavior.
        let enclave = EnclaveBuilder::from(ENCLAVE).debug(true).create().unwrap();

        let mut sum: c_int = 3;
        let result = unsafe { ecall_add_2(*enclave.get_id(), 3, &mut sum) };
        assert_eq!(result, sgx_status_t::SGX_SUCCESS);
        assert_eq!(sum, 3 + 2);
    }

    #[test]
    fn default_debug_flag_is_0() {
        // For the debug flag it's not easy, in a unit test, to test it was
        // passed to `sgx_create_enclave()`, instead we focus on the
        // `as c_int` portion maps correctly to 0 or 1
        let builder = EnclaveBuilder::from(b"");
        assert_eq!(builder.debug as c_int, 0);
    }

    #[test]
    fn when_debug_flag_is_true_it_is_1() {
        let builder = EnclaveBuilder::from(b"").debug(true);
        assert_eq!(builder.debug as c_int, 1);
    }
}
