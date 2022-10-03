// Copyright (c) 2022 MobileCoin Foundation

//! Provides functionality for interacting with the quoting enclaves.  The
//! QE(Quoting Enclave), PCE(Provisioning Certificate Enclave), and the
//! QPL(Quote Provider Library)
//!
//! Note: The <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
//! has a mix up.  It uses the *verification* description for `sgx_ql_set_path`
//! and the "generation" description for `sgx_qv_set_path`

use mc_sgx_core_sys_types::sgx_target_info_t;
use mc_sgx_core_types::TargetInfo;
use mc_sgx_dcap_ql_types::PathKind;
use mc_sgx_dcap_types::{Quote3Error, RequestPolicy};
use mc_sgx_util::ResultInto;
use std::{ffi::CString, os::unix::ffi::OsStrExt, path::Path};

/// Target info for quoting enclave
pub trait QeTargetInfo {
    /// The target info of the QE(Quoting Enclave)
    fn for_quoting_enclave() -> Result<TargetInfo, Quote3Error> {
        let mut info = sgx_target_info_t::default();
        unsafe { mc_sgx_dcap_ql_sys::sgx_qe_get_target_info(&mut info) }.into_result()?;
        Ok(info.into())
    }
}

impl QeTargetInfo for TargetInfo {}

/// Set path for QE(Quoting Enclave), PCE(Provisioning Certificate Enclave) or
/// QPL(Quote Provider Library)
///
/// This allows one to override the path that will be searched for each
/// `path_kind`.  When this isn't called then the local path and dlopen search
/// path will be utilized.
///
/// Returns [`Quote3Error`] when
/// * `path` does not point to a file
/// * `path` is longer than 259 (bytes)
/// * `path` contains a null (0) byte.
///
/// # Arguments
/// * `path_type` - Which path to set
/// * `path` - The path value to use.  This is the full path to a file.
pub fn set_path<P: AsRef<Path>>(path_kind: PathKind, path: P) -> Result<(), Quote3Error> {
    let c_path = CString::new(path.as_ref().as_os_str().as_bytes())
        .map_err(|_| Quote3Error::InvalidParameter)?;
    unsafe { mc_sgx_dcap_ql_sys::sgx_ql_set_path(path_kind.into(), c_path.as_ptr()) }.into_result()
}

/// Set the load policy
///
/// # Arguments
/// * `policy` - The policy to use for loading quoting enclaves
pub fn load_policy(policy: RequestPolicy) -> Result<(), Quote3Error> {
    unsafe { mc_sgx_dcap_ql_sys::sgx_qe_set_enclave_load_policy(policy.into()) }.into_result()
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_dcap_ql_types::PathKind::{
        ProvisioningCertificateEnclave, QuoteProviderLibrary, QuotingEnclave,
    };
    use std::fs;
    use tempfile::tempdir;
    use yare::parameterized;

    #[parameterized(
    qe = { QuotingEnclave },
    qpl = { QuoteProviderLibrary },
    pce = { ProvisioningCertificateEnclave },
    )]
    fn path_succeeds(path_kind: PathKind) {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake.txt");
        fs::write(&file_name, "stuff").unwrap();
        assert_eq!(set_path(path_kind, file_name), Ok(()));
    }

    #[test]
    fn qpl_path_succeeds() {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake.txt");
        fs::write(&file_name, "stuff").unwrap();
        assert_eq!(set_path(QuoteProviderLibrary, file_name), Ok(()));
    }

    #[test]
    fn path_as_directory_fails() {
        let dir = tempdir().unwrap();
        assert!(set_path(QuotingEnclave, dir.path()).is_err());
    }

    #[test]
    fn path_with_0_byte_fails_in_c_string() {
        let dir = tempdir().unwrap();
        let file_name = dir.path().join("fake\0.txt");
        // fs::write() will fail to create the file with a null byte in the path
        // so we pass the path as non existent to `set_path`.
        assert!(set_path(ProvisioningCertificateEnclave, file_name).is_err());
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

        assert!(set_path(QuoteProviderLibrary, file_name).is_ok());
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

        assert!(set_path(QuoteProviderLibrary, file_name).is_err());
    }

    #[parameterized(
    persistent = { RequestPolicy::Persistent },
    ephemeral = { RequestPolicy::Ephemeral },
    )]
    fn load_policy_succeeds(policy: RequestPolicy) {
        assert!(load_policy(policy).is_ok());
    }
}

#[cfg(all(test, not(feature = "sim")))]
mod hw_test {
    use super::*;
    use crate::set_path;
    use mc_sgx_dcap_ql_types::PathKind::{
        IdEnclave, ProvisioningCertificateEnclave, QuotingEnclave,
    };

    #[test]
    fn getting_target_info() {
        set_path(
            ProvisioningCertificateEnclave,
            "/usr/lib/x86_64-linux-gnu/libsgx_pce.signed.so.1",
        )
        .unwrap();
        set_path(
            QuotingEnclave,
            "/usr/lib/x86_64-linux-gnu/libsgx_qe3.signed.so.1",
        )
        .unwrap();
        set_path(
            IdEnclave,
            "/usr/lib/x86_64-linux-gnu/libsgx_id_enclave.signed.so.1",
        )
        .unwrap();
        assert!(TargetInfo::for_quoting_enclave().is_ok());
    }
}
