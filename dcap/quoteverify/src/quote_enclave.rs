// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Provides functionality for interacting with the quoting enclaves.  Both the
//! QVE(Quote Verification Enclave) and the QPL(Quote Provider Library).
//!
//! Note: The <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
//! has a mix up.  It uses the *verification* description for `sgx_ql_set_path`
//! and the "generation" description for `sgx_qv_set_path`

use crate::Error;
use mc_sgx_dcap_quoteverify_types::PathKind;
use mc_sgx_dcap_types::RequestPolicy;
use mc_sgx_util::ResultInto;
use once_cell::sync::Lazy;
use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path, sync::Mutex};

// Using the value from SGX to validate inputs and provide better error
// messages.
// NB: This should be checked once converted to a CString as it's the number of
//  bytes (+ NULL), not the number of characters.
const MAX_PATH_LENGTH: usize = 260;

/// A convenience type alias for a [`Result`](core::result::Result) which
/// contains an [`Error`].
pub type Result<T> = core::result::Result<T, Error>;

/// Initialization of the paths for the quote verification enclave and quote
/// provider library
///
/// This should only be called once during process start up utilizing
/// [`PathInitializer::with_paths()`] or [`PathInitializer::try_default()`].
/// If a consumer of this crate does not explicitly initialize the paths, then
/// they will be defaulted on the first call to an SGX function that needs the
/// paths set.
#[derive(Debug)]
pub struct PathInitializer;

static PATH_INITIALIZER: Lazy<Mutex<Option<PathInitializer>>> = Lazy::new(|| Mutex::new(None));

impl PathInitializer {
    /// Try to initialize the paths to the default for the system
    ///
    /// # Errors
    /// * [`Error::PathsInitialized`] if the paths have been previously
    ///   initialized.
    /// * [`Error::QuoteLibrary`] if any of the default paths don't exist on the system.
    pub fn try_default() -> Result<()> {
        // SGX has internal defaults with fallbacks, so we pass `None` for both
        // paths.
        Self::with_paths(None::<&Path>, None::<&Path>)
    }

    /// Initialize the DCAP quote verification library paths with provided
    /// values
    ///
    /// # Arguments
    /// * `quote_verification_enclave` - The full file path to the quote
    ///   verification enclave. If `None` then the default quote verification
    ///   enclave, which is embedded in the quote verification library, will be
    ///   used.
    /// * `quote_provider_library` - The full file path to the quote provider
    ///   library.  When this is `None` then the quote provider library found in
    ///   the system path will be used.
    ///
    /// # Errors
    /// * [`Error::PathsInitialized`] if the paths have been previously
    ///   initialized.
    /// * [`Error::PathStringConversion`] if one of the paths cannot be
    ///   converted to a [`CString`]
    /// * [`Error::QuoteLibrary`] if
    ///     * one of the paths does not point to a file
    ///     * one of the paths is longer than 259 (bytes)
    ///     * one of the paths contains a null (0) byte.
    pub fn with_paths<P1, P2>(
        quote_verification_enclave: Option<P1>,
        quote_provider_library: Option<P2>,
    ) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
    {
        let mut value = PATH_INITIALIZER.lock().expect("Mutex has been poisoned");
        if value.is_none() {
            quote_verification_enclave.map_or(Ok(()), |path| {
                Self::set_path(PathKind::QuoteVerificationEnclave, path)
            })?;
            quote_provider_library.map_or(Ok(()), |path| {
                Self::set_path(PathKind::QuoteProviderLibrary, path)
            })?;
            *value = Some(PathInitializer);
            Ok(())
        } else {
            Err(Error::PathsInitialized)
        }
    }

    /// Ensures the paths have been initialized
    ///
    /// If the paths have not been initialized will initialize to the default.
    ///
    /// # Errors
    /// Will return [`Error::QuoteLibrary`] if the paths have not been initialized and
    /// the default paths don't exist.
    ///
    /// Will *not* return an error if the paths were previously initialized.
    pub(crate) fn ensure_initialized() -> Result<()> {
        match Self::try_default() {
            Ok(_) | Err(Error::PathsInitialized) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Set path for QVE(Quoting Verification Enclave) or
    /// QPL(Quote Provider Library)
    ///
    /// This allows one to override the path that will be searched for each
    /// `path_kind`.  When this isn't called then the local path and dlopen
    /// search path will be utilized.
    ///
    /// # Arguments
    /// * `path_kind` - Which path to set
    /// * `path` - The path value to use.  This is the full path to a file.
    ///
    /// # Errors
    /// * [`Error::PathStringConversion`] if `path_kind` cannot be converted to
    ///   a [`CString`]
    /// * [`Error::QuoteLibrary`] if
    ///     * `path` does not point to a file
    ///     * `path` is longer than 259 (bytes)
    ///     * `path` contains a null (0) byte.
    fn set_path<P: AsRef<Path>>(path_kind: PathKind, path: P) -> Result<()> {
        let path = path.as_ref();
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| Error::PathStringConversion(path.to_string_lossy().into_owned()))?;

        path.is_file()
            .then_some(true)
            .ok_or_else(|| Error::PathDoesNotExist(path.to_string_lossy().into_owned()))?;

        if c_path.as_bytes_with_nul().len() > MAX_PATH_LENGTH {
            return Err(Error::PathLengthTooLong(
                path.to_string_lossy().into_owned(),
            ));
        }

        unsafe { mc_sgx_dcap_quoteverify_sys::sgx_qv_set_path(path_kind.into(), c_path.as_ptr()) }
            .into_result()?;
        Ok(())
    }
}

/// Initialization of the load policy for the quote verification enclave
///
/// This should only be called once during process start up utilizing
/// [`LoadPolicyInitializer::policy()`] or
/// [`LoadPolicyInitializer::try_default()`]. If a consumer of this crate does
/// not explicitly initialize the policy, then it will be the default SGX policy
/// of [`RequestPolicy::Persistent`].
#[derive(Debug)]
pub struct LoadPolicyInitializer;
static LOAD_POLICY_INITIALIZER: Lazy<Mutex<Option<LoadPolicyInitializer>>> =
    Lazy::new(|| Mutex::new(None));

impl LoadPolicyInitializer {
    /// Try to initialize the quote verification enclave load policy to the
    /// default
    ///
    /// The default is [`RequestPolicy::Persistent`].
    ///
    /// # Errors
    /// * [`Error::LoadPolicyInitialized`] if the policy has been previously
    ///   initialized.
    /// * [`Error::QuoteLibrary`] for any errors setting the policy in the SGX SDK.
    pub fn try_default() -> Result<()> {
        Self::policy(RequestPolicy::Persistent)
    }

    /// Set the load policy to use for the quote verification enclave
    ///
    /// # Arguments
    /// * `policy` - The policy to use for loading the quote verification
    ///   enclave
    ///
    /// # Errors
    /// * [`Error::LoadPolicyInitialized`] if the policy has been previously
    ///   initialized.
    /// * [`Error::QuoteLibrary`] for any errors setting the policy in the SGX SDK.
    pub fn policy(policy: RequestPolicy) -> Result<()> {
        let mut value = LOAD_POLICY_INITIALIZER
            .lock()
            .expect("Mutex has been poisoned");
        if value.is_none() {
            unsafe { mc_sgx_dcap_quoteverify_sys::sgx_qv_set_enclave_load_policy(policy.into()) }
                .into_result()?;
            *value = Some(LoadPolicyInitializer);
            Ok(())
        } else {
            Err(Error::LoadPolicyInitialized)
        }
    }

    /// Will ensure the load policy has been explicity set
    ///
    /// If the load policy has already been set does nothing
    ///
    /// # Errors
    /// Will return [`Error::QuoteLibrary`] if the load policy has not been initialized
    /// and there is an error setting the policy
    ///
    /// Will *not* return an error if the load policy as previously initialized.
    pub(crate) fn ensure_initialized() -> Result<()> {
        match Self::try_default() {
            Ok(_) | Err(Error::LoadPolicyInitialized) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_dcap_quoteverify_types::PathKind::{QuoteProviderLibrary, QuoteVerificationEnclave};
    use serial_test::serial;
    use std::fs;
    use tempfile::tempdir;

    /// Resets the [`PATH_INITIALIZER`] to being uninitialized.
    /// Since there is *one* [`PATH_INITIALIZER`] for the entire test process
    /// any tests focusing on the functionality of the [`PATH_INITIALIZER`]
    /// should be utilizing the `#[serial]` macro.
    fn reset_path_initializer() {
        let mut value = PATH_INITIALIZER.lock().expect("Mutex has been poisoned");
        *value = None;
    }

    #[test]
    fn qve_path_succeeds() {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake.txt");
        fs::write(&file_name, "stuff").unwrap();
        assert!(PathInitializer::set_path(QuoteVerificationEnclave, file_name).is_ok());
    }

    #[test]
    fn qpl_path_succeeds() {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake.txt");
        fs::write(&file_name, "stuff").unwrap();
        assert!(PathInitializer::set_path(QuoteProviderLibrary, file_name).is_ok());
    }

    #[test]
    fn path_as_directory_fails() {
        let dir = tempdir().unwrap();
        assert!(PathInitializer::set_path(QuoteVerificationEnclave, dir.path()).is_err());
    }

    #[test]
    fn path_with_0_byte_fails_in_c_string() {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake\0.txt");
        // fs::write() will fail to create the file with a null byte in the path
        // so we pass the path as non existent to `set_path`.
        assert!(PathInitializer::set_path(QuoteVerificationEnclave, file_name).is_err());
    }

    #[test]
    fn path_length_at_max_ok() {
        const MAX_PATH: usize = 259;
        let dir = tempdir().unwrap();
        let mut dir_length = dir.path().as_os_str().as_bytes().len();
        dir_length += 1; // for the joining "/"

        let long_name = str::repeat("a", MAX_PATH - dir_length);
        let file_name = dir.path().join(long_name);
        fs::write(&file_name, "stuff").unwrap();

        assert!(PathInitializer::set_path(QuoteProviderLibrary, file_name).is_ok());
    }

    #[test]
    fn path_length_exceeded() {
        const MAX_PATH: usize = 259;
        let dir = tempdir().unwrap();
        let mut dir_length = dir.path().as_os_str().as_bytes().len();
        dir_length += 1; // for the joining "/"

        let long_name = str::repeat("a", (MAX_PATH + 1) - dir_length);
        let file_name = dir.path().join(long_name);
        fs::write(&file_name, "stuff").unwrap();

        assert!(PathInitializer::set_path(QuoteProviderLibrary, file_name).is_err());
    }

    #[test]
    #[serial]
    fn default_path_initializer_succeeds() {
        reset_path_initializer();
        let result = PathInitializer::try_default();
        assert_eq!(result, Ok(()));
    }

    #[test]
    #[serial]
    fn default_path_initializer_fails_when_already_initialized() {
        reset_path_initializer();
        PathInitializer::try_default().unwrap();
        let result = PathInitializer::try_default();
        assert_eq!(result, Err(Error::PathsInitialized));
    }

    #[test]
    #[serial]
    fn with_paths_path_initializer_succeeds() {
        let dir = tempdir().unwrap();
        let names = ["1", "2"]
            .into_iter()
            .map(|name| {
                let file_name = dir.path().join(name);
                fs::write(&file_name, name).unwrap();
                file_name
            })
            .collect::<Vec<_>>();

        reset_path_initializer();
        let result = PathInitializer::with_paths(Some(&names[0]), Some(&names[1]));
        assert_eq!(result, Ok(()));
    }

    #[test]
    #[serial]
    fn with_paths_after_default_fails() {
        let dir = tempdir().unwrap();
        let names = ["1", "2"]
            .into_iter()
            .map(|name| {
                let file_name = dir.path().join(name);
                fs::write(&file_name, name).unwrap();
                file_name
            })
            .collect::<Vec<_>>();

        reset_path_initializer();
        PathInitializer::try_default().unwrap();
        let result = PathInitializer::with_paths(Some(&names[0]), Some(&names[1]));
        assert_eq!(result, Err(Error::PathsInitialized));
    }

    #[test]
    #[serial]
    fn with_paths_more_than_once_fails() {
        let dir = tempdir().unwrap();
        let names = ["a", "b"]
            .into_iter()
            .map(|name| {
                let file_name = dir.path().join(name);
                fs::write(&file_name, name).unwrap();
                file_name
            })
            .collect::<Vec<_>>();

        reset_path_initializer();
        PathInitializer::with_paths(Some(&names[0]), Some(&names[1])).unwrap();
        let result = PathInitializer::with_paths(Some(&names[0]), Some(&names[1]));
        assert_eq!(result, Err(Error::PathsInitialized));
    }

    #[test]
    #[serial]
    fn bad_path_fails_and_can_be_retried() {
        const MAX_PATH: usize = 259;
        let dir = tempdir().unwrap();
        let mut dir_length = dir.path().as_os_str().as_bytes().len();
        dir_length += 1; // for the joining "/"
        let long_name = str::repeat("a", (MAX_PATH + 1) - dir_length);
        let mut names = [&long_name, "b"]
            .into_iter()
            .map(|name| {
                let file_name = dir.path().join(name);
                fs::write(&file_name, name).unwrap();
                file_name
            })
            .collect::<Vec<_>>();

        for _ in 0..names.len() {
            names.rotate_right(1);
            reset_path_initializer();
            let result = PathInitializer::with_paths(Some(&names[0]), Some(&names[1]));
            assert!(matches!(result, Err(Error::PathLengthTooLong(_))));

            assert_eq!(PathInitializer::try_default(), Ok(()));
        }
    }

    #[test]
    #[serial]
    fn ensuring_paths_initialized_succeeds_when_already_initialized() {
        reset_path_initializer();
        PathInitializer::try_default().unwrap();
        assert_eq!(PathInitializer::ensure_initialized(), Ok(()));
    }

    #[test]
    fn load_policy() {
        // The load policy can only be set once per process, as such this is a
        // bit of a workflow test and no other test can set or change the load
        // policy.
        //
        // The workflow is:
        // 1. The first call to set the policy should succeed.
        // 2. The next call to set the policy should result in an initialized
        //    error.
        // 3. Ensuring the policy is initialized should *not* result in an
        //    error if it's already been initialized.

        assert_eq!(
            LoadPolicyInitializer::policy(RequestPolicy::Ephemeral),
            Ok(())
        );
        assert_eq!(
            LoadPolicyInitializer::policy(RequestPolicy::Ephemeral),
            Err(Error::LoadPolicyInitialized)
        );
        assert_eq!(LoadPolicyInitializer::ensure_initialized(), Ok(()));
    }
}
