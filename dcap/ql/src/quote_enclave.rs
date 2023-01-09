// Copyright (c) 2022-2023 The MobileCoin Foundation

//! Provides functionality for interacting with the quoting enclaves.  The
//! QE(Quoting Enclave), PCE(Provisioning Certificate Enclave), and the
//! QPL(Quote Provider Library)
//!
//! Note: The <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
//! has a mix up.  It uses the *verification* description for `sgx_ql_set_path`
//! and the "generation" description for `sgx_qv_set_path`

use crate::Error;
use mc_sgx_core_sys_types::sgx_target_info_t;
use mc_sgx_core_types::TargetInfo;
use mc_sgx_dcap_ql_types::PathKind;
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

/// Initialization of the paths for the quoting enclaves and quote provider
/// library
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
    /// Currently the defaults assume the default DCAP install on an Ubuntu
    /// machine.
    ///
    /// # Errors
    /// * [`Error::PathsInitialized`] if the paths have been previously
    ///   initialized.
    /// * [`Error::QuoteLibrary`] if any of the default paths don't exist on the system.
    pub fn try_default() -> Result<()> {
        Self::with_paths(
            "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so.1",
            "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1",
            None::<&Path>,
            "/usr/lib/x86_64-linux-gnu/libsgx_id_enclave.signed.so.1",
        )
    }

    /// Initialize the DCAP quoting library paths with provided values
    ///
    /// # Arguments
    /// * `quoting_enclave` - The full file path to the quoting enclave
    /// * `provisioning_certificate_enclave` - The full file path to the
    ///   provisioning certificate enclave
    /// * `quote_provider_library` - The full file path to the quote provider
    ///   library.  When this is `None` then no quote provider library will be
    ///   used limiting quote generation to local quote generation only.
    /// * `id_enclave` - The full file path to the ID enclave.
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
    pub fn with_paths<P1, P2, P3, P4>(
        quoting_enclave: P1,
        provisioning_certificate_enclave: P2,
        quote_provider_library: Option<P3>,
        id_enclave: P4,
    ) -> Result<()>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
        P3: AsRef<Path>,
        P4: AsRef<Path>,
    {
        let mut value = PATH_INITIALIZER.lock().expect("Mutex has been poisoned");
        if value.is_none() {
            Self::set_paths(
                quoting_enclave,
                provisioning_certificate_enclave,
                quote_provider_library,
                id_enclave,
            )?;
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

    fn set_paths<P1, P2, P3, P4>(
        quoting_enclave: P1,
        provisioning_certificate_enclave: P2,
        quote_provider_library: Option<P3>,
        id_enclave: P4,
    ) -> Result<PathInitializer>
    where
        P1: AsRef<Path>,
        P2: AsRef<Path>,
        P3: AsRef<Path>,
        P4: AsRef<Path>,
    {
        Self::set_path(PathKind::QuotingEnclave, quoting_enclave)?;
        Self::set_path(
            PathKind::ProvisioningCertificateEnclave,
            provisioning_certificate_enclave,
        )?;
        Self::set_path(PathKind::IdEnclave, id_enclave)?;
        quote_provider_library.map_or(Ok(()), |path| {
            Self::set_path(PathKind::QuoteProviderLibrary, path)
        })?;
        Ok(PathInitializer)
    }

    /// Set path for QE(Quoting Enclave), PCE(Provisioning Certificate Enclave)
    /// or QPL(Quote Provider Library)
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

        unsafe { mc_sgx_dcap_ql_sys::sgx_ql_set_path(path_kind.into(), c_path.as_ptr()) }
            .into_result()?;
        Ok(())
    }
}

/// Target info for quoting enclave
pub trait QeTargetInfo {
    /// The target info of the QE(Quoting Enclave)
    ///
    /// Note: This will initialize the [`PathInitializer`] and
    ///   [`LoadPolicyInitializer`] to the defaults if they have not been
    ///   initialized yet. Attempts to initialize [`PathInitializer`] or
    ///   [`LoadPolicyInitializer`] after calling this function will result in
    ///   an error.
    ///
    /// # Errors
    /// Will return an error if there is a failure from the SGX SDK
    fn for_quoting_enclave() -> Result<TargetInfo> {
        PathInitializer::ensure_initialized()?;
        LoadPolicyInitializer::ensure_initialized()?;
        let mut info = sgx_target_info_t::default();
        unsafe { mc_sgx_dcap_ql_sys::sgx_qe_get_target_info(&mut info) }.into_result()?;
        Ok(info.into())
    }
}

impl QeTargetInfo for TargetInfo {}

/// Initialization of the load policy for the quoting enclaves
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
    /// Try to initialize the quoting enclave load policy to the default
    ///
    /// The default is persistent [`RequestPolicy::Persistent`].
    ///
    /// # Errors
    /// * [`Error::LoadPolicyInitialized`] if the policy has been previously
    ///   initialized.
    /// * [`Error::QuoteLibrary`] for any errors setting the policy in the SGX SDK.
    pub fn try_default() -> Result<()> {
        Self::policy(RequestPolicy::Persistent)
    }

    /// Set the load policy to use for the quoting enclaves
    ///
    /// # Arguments
    /// * `policy` - The policy to use for loading the quoting enclaves
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
            unsafe { mc_sgx_dcap_ql_sys::sgx_qe_set_enclave_load_policy(policy.into()) }
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
    use mc_sgx_dcap_ql_types::PathKind::{
        ProvisioningCertificateEnclave, QuoteProviderLibrary, QuotingEnclave,
    };
    use serial_test::serial;
    use std::fs;
    use tempfile::tempdir;
    use yare::parameterized;

    /// Resets the [`PATH_INITIALIZER`] to being uninitialized.
    /// Since there is *one* [`PATH_INITIALIZER`] for the entire test process
    /// any tests focusing on the functionality of the [`PATH_INITIALIZER`]
    /// should be utilizing the `#[serial]` macro.
    fn reset_path_initializer() {
        let mut value = PATH_INITIALIZER.lock().expect("Mutex has been poisoned");
        *value = None;
    }

    /// Resets the [`LOAD_POLICY_INITIALIZER`] to being uninitialized.
    /// Since there is *one* [`LOAD_POLICY_INITIALIZER`] for the entire test
    /// process any tests focusing on the functionality of the
    /// [`LOAD_POLICY_INITIALIZER`] should be utilizing the `#[serial]` macro.
    fn reset_load_policy_initializer() {
        let mut value = LOAD_POLICY_INITIALIZER
            .lock()
            .expect("Mutex has been poisoned");
        *value = None;
    }

    #[parameterized(
    qe = { QuotingEnclave },
    qpl = { QuoteProviderLibrary },
    pce = { ProvisioningCertificateEnclave },
    )]
    fn path_succeeds(path_kind: PathKind) {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake.txt");
        fs::write(&file_name, "stuff").unwrap();
        assert_eq!(PathInitializer::set_path(path_kind, file_name), Ok(()));
    }

    #[test]
    fn qpl_path_succeeds() {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake.txt");
        fs::write(&file_name, "stuff").unwrap();
        assert_eq!(
            PathInitializer::set_path(QuoteProviderLibrary, file_name),
            Ok(())
        );
    }

    #[test]
    fn path_as_directory_fails() {
        let dir = tempdir().unwrap();
        assert_eq!(
            PathInitializer::set_path(QuotingEnclave, dir.path()),
            Err(Error::PathDoesNotExist(String::from(
                dir.path().to_str().unwrap()
            )))
        );
    }

    #[test]
    fn path_with_0_byte_fails_in_c_string() {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake\0.txt");
        // fs::write() will fail to create the file with a null byte in the path
        // so we pass the path as non existent to `set_path`.
        assert_eq!(
            PathInitializer::set_path(ProvisioningCertificateEnclave, &file_name),
            Err(Error::PathStringConversion(String::from(
                file_name.to_string_lossy()
            )))
        );
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

        assert_eq!(
            PathInitializer::set_path(QuoteProviderLibrary, &file_name),
            Err(Error::PathLengthTooLong(String::from(
                file_name.to_str().unwrap()
            )))
        );
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
        let names = ["1", "2", "3", "4"]
            .into_iter()
            .map(|name| {
                let file_name = dir.path().join(name);
                fs::write(&file_name, name).unwrap();
                file_name
            })
            .collect::<Vec<_>>();

        reset_path_initializer();
        let result = PathInitializer::with_paths(&names[0], &names[1], Some(&names[2]), &names[3]);
        assert_eq!(result, Ok(()));
    }

    #[test]
    #[serial]
    fn with_paths_after_default_fails() {
        let dir = tempdir().unwrap();
        let names = ["1", "2", "3", "4"]
            .into_iter()
            .map(|name| {
                let file_name = dir.path().join(name);
                fs::write(&file_name, name).unwrap();
                file_name
            })
            .collect::<Vec<_>>();

        reset_path_initializer();
        PathInitializer::try_default().unwrap();
        let result = PathInitializer::with_paths(&names[0], &names[1], Some(&names[2]), &names[3]);
        assert_eq!(result, Err(Error::PathsInitialized));
    }

    #[test]
    #[serial]
    fn with_paths_more_than_once_fails() {
        let dir = tempdir().unwrap();
        let names = ["a", "b", "c", "d"]
            .into_iter()
            .map(|name| {
                let file_name = dir.path().join(name);
                fs::write(&file_name, name).unwrap();
                file_name
            })
            .collect::<Vec<_>>();

        reset_path_initializer();
        PathInitializer::with_paths(&names[0], &names[1], Some(&names[2]), &names[3]).unwrap();
        let result = PathInitializer::with_paths(&names[0], &names[1], Some(&names[2]), &names[3]);
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
        let mut names = [&long_name, "b", "c", "d"]
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
            let result =
                PathInitializer::with_paths(&names[0], &names[1], Some(&names[2]), &names[3]);
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

    #[parameterized(
    persistent = { RequestPolicy::Persistent },
    ephemeral = { RequestPolicy::Ephemeral },
    )]
    #[serial]
    fn load_policy_succeeds(policy: RequestPolicy) {
        reset_load_policy_initializer();
        assert_eq!(LoadPolicyInitializer::policy(policy), Ok(()));
    }

    #[test]
    #[serial]
    fn load_policy_fails_when_already_initialized() {
        reset_load_policy_initializer();
        LoadPolicyInitializer::try_default().unwrap();
        assert_eq!(
            LoadPolicyInitializer::try_default(),
            Err(Error::LoadPolicyInitialized)
        );
    }

    #[test]
    #[serial]
    fn ensuring_the_policy_is_set_is_ok_when_already_set() {
        reset_load_policy_initializer();
        LoadPolicyInitializer::policy(RequestPolicy::Ephemeral).unwrap();
        assert_eq!(LoadPolicyInitializer::ensure_initialized(), Ok(()));
    }
}

#[cfg(all(test, not(feature = "sim")))]
mod hw_test {
    use super::*;

    #[test]
    fn getting_target_info() {
        assert!(TargetInfo::for_quoting_enclave().is_ok());
    }
}
