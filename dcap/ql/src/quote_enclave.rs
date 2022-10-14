// Copyright (c) 2022 MobileCoin Foundation

//! Provides functionality for interacting with the quoting enclaves.  The
//! QE(Quoting Enclave), PCE(Provisioning Certificate Enclave), and the
//! QPL(Quote Provider Library)
//!
//! Note: The <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
//! has a mix up.  It uses the *verification* description for `sgx_ql_set_path`
//! and the "generation" description for `sgx_qv_set_path`

use crate::Error;
use core::result::Result as CoreResult;
use mc_sgx_core_sys_types::sgx_target_info_t;
use mc_sgx_core_types::TargetInfo;
use mc_sgx_dcap_ql_types::PathKind;
use mc_sgx_dcap_types::RequestPolicy;
use mc_sgx_util::ResultInto;
use once_cell::sync::Lazy;
use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path, sync::Mutex};

/// A convenience type alias for a `Result` which contains an [`Error`].
pub type Result<T> = CoreResult<T, Error>;

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
    /// * [`Error::Sgx`] if any of the default paths don't exist on the system.
    pub fn try_default() -> Result<()> {
        Self::with_paths(
            "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so.1",
            "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1",
            None,
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
    /// * [`Error::Sgx`] if
    ///     * one of the paths does not point to a file
    ///     * one of the paths is longer than 259 (bytes)
    ///     * one of the paths contains a null (0) byte.
    pub fn with_paths<P: AsRef<Path>>(
        quoting_enclave: P,
        provisioning_certificate_enclave: P,
        quote_provider_library: Option<P>,
        id_enclave: P,
    ) -> Result<()> {
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

    /// Will ensure the paths have been initialized
    ///
    /// If the paths have not been initialized will initialize to the default.
    ///
    /// # Errors
    /// Will return [`Error::Sgx`] if the paths have not been initialized and
    /// the default paths don't exist.
    ///
    /// Will *not* return an error if the paths were previously initialized.
    pub(crate) fn ensure_initialized() -> Result<()> {
        match Self::try_default() {
            Ok(_) | Err(Error::PathsInitialized) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn set_paths<P: AsRef<Path>>(
        quoting_enclave: P,
        provisioning_certificate_enclave: P,
        quote_provider_library: Option<P>,
        id_enclave: P,
    ) -> Result<PathInitializer> {
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
    /// * [`Error::Sgx`] if
    ///     * `path` does not point to a file
    ///     * `path` is longer than 259 (bytes)
    ///     * `path` contains a null (0) byte.
    fn set_path<P: AsRef<Path>>(path_kind: PathKind, path: P) -> Result<()> {
        let c_path = CString::new(path.as_ref().as_os_str().as_bytes()).map_err(|_| {
            Error::PathStringConversion(path.as_ref().to_string_lossy().into_owned())
        })?;
        unsafe { mc_sgx_dcap_ql_sys::sgx_ql_set_path(path_kind.into(), c_path.as_ptr()) }
            .into_result()?;
        Ok(())
    }
}

/// Target info for quoting enclave
pub trait QeTargetInfo {
    /// The target info of the QE(Quoting Enclave)
    ///
    /// Note: This will initialized the [`PathInitializer`] to the
    ///   defaults if the [`PathInitializer`] has not been initialized yet.
    ///   Calling [`PathInitializer::with_paths()`] after calling this function
    ///   will result in an error.
    ///
    /// # Errors
    /// Will return an error if there is a failure from the SGX SDK
    fn for_quoting_enclave() -> Result<TargetInfo> {
        PathInitializer::ensure_initialized()?;
        let mut info = sgx_target_info_t::default();
        unsafe { mc_sgx_dcap_ql_sys::sgx_qe_get_target_info(&mut info) }.into_result()?;
        Ok(info.into())
    }
}

impl QeTargetInfo for TargetInfo {}

/// Set the load policy
///
/// # Arguments
/// * `policy` - The policy to use for loading quoting enclaves
pub fn load_policy(policy: RequestPolicy) -> Result<()> {
    unsafe { mc_sgx_dcap_ql_sys::sgx_qe_set_enclave_load_policy(policy.into()) }.into_result()?;
    Ok(())
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
        assert!(PathInitializer::set_path(QuotingEnclave, dir.path()).is_err());
    }

    #[test]
    fn path_with_0_byte_fails_in_c_string() {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake\0.txt");
        // fs::write() will fail to create the file with a null byte in the path
        // so we pass the path as non existent to `set_path`.
        assert!(PathInitializer::set_path(ProvisioningCertificateEnclave, file_name).is_err());
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

    #[parameterized(
    persistent = { RequestPolicy::Persistent },
    ephemeral = { RequestPolicy::Ephemeral },
    )]
    fn load_policy_succeeds(policy: RequestPolicy) {
        assert!(load_policy(policy).is_ok());
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
}

#[cfg(all(test, not(feature = "sim")))]
mod hw_test {
    use super::*;

    #[test]
    fn getting_target_info() {
        assert!(TargetInfo::for_quoting_enclave().is_ok());
    }
}
