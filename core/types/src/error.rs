// Copyright (c) 2022 The MobileCoin Foundation

//! SGX Error types

use core::convert::From;
use mc_sgx_core_sys_types::sgx_status_t;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Errors seen when converting to, or from, rust for the SGX types
#[derive(Debug)]
pub enum FfiError {
    /// Enum out of range
    /// Happens when a value that is not represented by the known C enum values.
    UnknownEnumValue(i64),
}

/// A enumeration of SGX errors.
///
/// Those listed here are the ones which are identified in the `sgx_status_t`
/// enum, in order of the actual value. Note that values are grouped
/// (numerically) into the following general sections:
///
///  1. `0x0000-0x0fff`: Generic errors.
///  2. `0x1000-0x1fff`: Fatal runtime errors.
///  3. `0x2000-0x2fff`: Enclave creation errors.
///  4. `0x3000-0x3fff`: Local attestation/report verification errors.
///  5. `0x4000-0x4fff`: Errors when communicating with the Architectural
///                      Enclave Service Manager (AESM).
///  6. `0x5000-0x5fff`: Errors internal to AESM.
///  7. `0x6000-0x6fff`: Errors with the encrypted enclave loader.
///  8. `0x7000-0x7fff`: Errors with the "SGX Encrypted FS" utility.
///  9. `0x8000-0x8fff`: Attestation key errors.
/// 10. `0xf000-0xffff`: Internal (to SGX) errors.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Error {
    // 0x0001 - 0x0fff: Generic errors
    /// An unexpected error.
    Unexpected,
    /// The parameter is incorrect.
    InvalidParameter,
    /// There is not enough memory available to complete this operation.
    OutOfMemory,
    /// The enclave was lost after power transition or used in a child process
    /// created by fork().
    EnclaveLost,
    /// The API is invoked in incorrect order or state.
    InvalidState,
    /// The feature is not supported.
    FeatureNotSupported,
    /// A thread in the enclave exited
    ThreadExit,
    /// Failed to reserve memory for the enclave
    MemoryMapFailure,

    // 0x1001 - 0x1fff: Fatal runtime errors
    /// The ECALL or OCALL function index is incorrect.
    InvalidFunction,
    /// The enclave is out of Thread Control Structures.
    OutOfTcs,
    /// The enclave crashed.
    EnclaveCrashed,
    /// ECALL is not allowed at this time.
    ///
    /// Possible reasons include:
    ///
    ///  * ECALL is not public.
    ///  * ECALL is blocked by the dynamic entry table.
    ///  * A nested ECALL is not allowed during global initialization.
    EcallNotAllowed,
    /// OCALL is not allowed during exception handling.
    OcallNotAllowed,
    /// Stack overrun occurs within the enclave.
    StackOverrun,

    // 0x2000 - 0x2fff: Enclave construction errors
    /// The enclave contains an undefined symbol.
    UndefinedSymbol,
    /// The enclave image has been corrupted.
    InvalidEnclave,
    /// The enclave ID is invalid.
    InvalidEnclaveId,
    /// The signature for the enclave is invalid.
    InvalidSignature,
    /// The enclave was signed as a production enclave, and cannot be
    /// instantiated as debuggable.
    NdebugEnclave,
    /// There is not enough EPC (encrypted page cache) available to load the
    /// enclave or one of the Architecture Enclaves needed to complete the
    /// operation requested.
    OutOfEpc,
    /// Cannot open the device.
    NoDevice,
    /// Page mapping failed in the driver.
    MemoryMapConflict,
    /// The metadata is incorrect.
    InvalidMetadata,
    /// The device is busy
    DeviceBusy,
    /// Metadata version is inconsistent between uRTS and
    /// `sgx_status_t::SGX_sign` or the uRTS is incompatible with the current
    /// platform.
    InvalidVersion,
    /// The target enclave mode (either 32 vs. 64-bit, or hardware vs.
    /// simulation) is incompatible with the untrusted mode.
    ModeIncompatible,
    /// Cannot open the enclave file.
    EnclaveFileAccess,
    /// The MiscSelect or MiscMask settings are incorrect.
    InvalidMisc,
    /// The launch token is incorrect.
    InvalidLaunchToken,

    // 0x3001-0x3fff: Report verification
    /// Report verification error.
    MacMismatch,
    /// The enclave is not authorized.
    InvalidAttribute,
    /// The CPU security version of this platform is too old.
    InvalidCpuSvn,
    /// The enclave security version is too old.
    InvalidIsvSvn,
    /// Unsupported key name value.
    InvalidKeyname,

    // 0x4000 - 0x4fff: AESM
    /// Architectural Enclave service does not respond or the requested service
    /// is not supported.
    ServiceUnavailable,
    /// The request to the Architectural Enclave service timed out.
    ServiceTimeout,
    /// Intel EPID blob verification error.
    AeInvalidEpidblob,
    /// Enclave has no privilege to get a launch token.
    ServiceInvalidPrivilege,
    /// The EPID group membership has been revoked .
    ///
    /// The platform is not trusted,and will not be trusted even if updated.
    EpidMemberRevoked,
    /// Intel SGX requires update.
    UpdateNeeded,
    /// Network or proxy issue.
    NetworkFailure,
    /// The Architectural Enclave session is invalid or ended by the server.
    AeSessionInvalid,
    /// The requested service is temporarily not available.
    Busy,
    /// The Monotonic Counter does not exist or has been invalidated.
    McNotFound,
    /// The caller does not have the access right to the specified Virtual
    /// Monotonic Counter.
    McNoAccessRight,
    /// No monotonic counter is available.
    McUsedUp,
    /// Monotonic counters reached quote limit.
    McOverQuota,
    /// Key derivation function did not match during key exchange.
    KdfMismatch,
    /// Intel EPID provisioning failed because the platform is not recognized by
    /// the back-end server.
    UnrecognizedPlatform,
    /// There are unsupported bits in the config.
    UnsupportedConfig,

    // 0x5000 - 0x5fff: AESM-internal errors
    /// The application does not have the privilege needed to read UEFI
    /// variables.
    NoPrivilege,

    // 0x6000 - 0x6fff: Encrypted Enclaves
    /// Trying to load an encrypted enclave using API or parameters for
    /// plaintext enclaves.
    PclEncrypted,
    /// Trying to load an enclave that is not encrypted with using API or
    /// parameters for encrypted enclaves.
    PclNotEncrypted,
    /// The runtime AES-GCM-128 MAC result of an encrypted section does not
    /// match the one used at build time.
    PclMacMismatch,
    /// The runtime SHA256 hash of the decryption key does not match the one
    /// used at build time.
    PclShaMismatch,
    /// The GUID in the decryption key sealed blob does not match the one used
    /// at build time.
    PclGuidMismatch,

    // 0x7000 - 0x7fff: SGX Encrypted FS
    /// The file is in a bad status, run sgx_status_t::SGX_clearerr to try and
    /// fix it.
    FileBadStatus,
    /// The Key ID field is all zeroes, the encryption key cannot be
    /// regenerated.
    FileNoKeyId,
    /// The current file name is different from the original file name
    /// (substitution attack).
    FileNameMismatch,
    /// The file is not an Intel SGX file.
    FileNotSgxFile,
    /// A recovery file cannot be opened, so the flush operation cannot
    /// continue.
    FileCantOpenRecoveryFile,
    /// A recovery file cannot be written, so the flush operation cannot
    /// continue.
    FileCantWriteRecoveryFile,
    /// When opening the file, recovery is needed, but the recovery process
    /// failed.
    FileRecoveryNeeded,
    /// The fflush() operation failed.
    FileFlushFailed,
    /// The fclose() operation failed.
    FileCloseFailed,

    // 0x8000-0x8fff: Custom Attestation support
    /// Platform quoting infrastructure does not support the key
    UnsupportedAttKeyId,
    /// Failed to generate and certify the attestation key.
    AttKeyCertificationFailure,
    /// The platform quoting infrastructure does not have the attestation key
    /// available to generate a quote.
    AttKeyUninitialized,
    /// The data returned by sgx_status_t::SGX_get_quote_config() is invalid.
    InvalidAttKeyCertData,
    /// The PCK cert for the platform is not available.
    PlatformCertUnavailable,

    // 0xf000-0xffff: Internal-to-SGX errors
    /// The ioctl for enclave_create unexpectedly failed with EINTR.
    EnclaveCreateInterrupted,
}

impl From<sgx_status_t> for Error {
    fn from(src: sgx_status_t) -> Error {
        match src {
            // 0x0001 - 0x0fff: Generic errors
            sgx_status_t::SGX_ERROR_UNEXPECTED => Error::Unexpected,
            sgx_status_t::SGX_ERROR_INVALID_PARAMETER => Error::InvalidParameter,
            sgx_status_t::SGX_ERROR_OUT_OF_MEMORY => Error::OutOfMemory,
            sgx_status_t::SGX_ERROR_ENCLAVE_LOST => Error::EnclaveLost,
            sgx_status_t::SGX_ERROR_INVALID_STATE => Error::InvalidState,
            sgx_status_t::SGX_ERROR_FEATURE_NOT_SUPPORTED => Error::FeatureNotSupported,
            sgx_status_t::SGX_PTHREAD_EXIT => Error::ThreadExit,
            sgx_status_t::SGX_ERROR_MEMORY_MAP_FAILURE => Error::MemoryMapFailure,

            // 0x1001 - 0x1fff: Fatal runtime errors
            sgx_status_t::SGX_ERROR_INVALID_FUNCTION => Error::InvalidFunction,
            sgx_status_t::SGX_ERROR_OUT_OF_TCS => Error::OutOfTcs,
            sgx_status_t::SGX_ERROR_ENCLAVE_CRASHED => Error::EnclaveCrashed,
            sgx_status_t::SGX_ERROR_ECALL_NOT_ALLOWED => Error::EcallNotAllowed,
            sgx_status_t::SGX_ERROR_OCALL_NOT_ALLOWED => Error::OcallNotAllowed,
            sgx_status_t::SGX_ERROR_STACK_OVERRUN => Error::StackOverrun,

            // 0x2000 - 0x2fff: Enclave construction errors
            sgx_status_t::SGX_ERROR_UNDEFINED_SYMBOL => Error::UndefinedSymbol,
            sgx_status_t::SGX_ERROR_INVALID_ENCLAVE => Error::InvalidEnclave,
            sgx_status_t::SGX_ERROR_INVALID_ENCLAVE_ID => Error::InvalidEnclaveId,
            sgx_status_t::SGX_ERROR_INVALID_SIGNATURE => Error::InvalidSignature,
            sgx_status_t::SGX_ERROR_NDEBUG_ENCLAVE => Error::NdebugEnclave,
            sgx_status_t::SGX_ERROR_OUT_OF_EPC => Error::OutOfEpc,
            sgx_status_t::SGX_ERROR_NO_DEVICE => Error::NoDevice,
            sgx_status_t::SGX_ERROR_MEMORY_MAP_CONFLICT => Error::MemoryMapConflict,
            sgx_status_t::SGX_ERROR_INVALID_METADATA => Error::InvalidMetadata,
            sgx_status_t::SGX_ERROR_DEVICE_BUSY => Error::DeviceBusy,
            sgx_status_t::SGX_ERROR_INVALID_VERSION => Error::InvalidVersion,
            sgx_status_t::SGX_ERROR_MODE_INCOMPATIBLE => Error::ModeIncompatible,
            sgx_status_t::SGX_ERROR_ENCLAVE_FILE_ACCESS => Error::EnclaveFileAccess,
            sgx_status_t::SGX_ERROR_INVALID_MISC => Error::InvalidMisc,
            sgx_status_t::SGX_ERROR_INVALID_LAUNCH_TOKEN => Error::InvalidLaunchToken,

            // 0x3001-0x3fff: Report verification
            sgx_status_t::SGX_ERROR_MAC_MISMATCH => Error::MacMismatch,
            sgx_status_t::SGX_ERROR_INVALID_ATTRIBUTE => Error::InvalidAttribute,
            sgx_status_t::SGX_ERROR_INVALID_CPUSVN => Error::InvalidCpuSvn,
            sgx_status_t::SGX_ERROR_INVALID_ISVSVN => Error::InvalidIsvSvn,
            sgx_status_t::SGX_ERROR_INVALID_KEYNAME => Error::InvalidKeyname,

            // 0x4000 - 0x4fff: AESM
            sgx_status_t::SGX_ERROR_SERVICE_UNAVAILABLE => Error::ServiceUnavailable,
            sgx_status_t::SGX_ERROR_SERVICE_TIMEOUT => Error::ServiceTimeout,
            sgx_status_t::SGX_ERROR_AE_INVALID_EPIDBLOB => Error::AeInvalidEpidblob,
            sgx_status_t::SGX_ERROR_SERVICE_INVALID_PRIVILEGE => Error::ServiceInvalidPrivilege,
            sgx_status_t::SGX_ERROR_EPID_MEMBER_REVOKED => Error::EpidMemberRevoked,
            sgx_status_t::SGX_ERROR_UPDATE_NEEDED => Error::UpdateNeeded,
            sgx_status_t::SGX_ERROR_NETWORK_FAILURE => Error::NetworkFailure,
            sgx_status_t::SGX_ERROR_AE_SESSION_INVALID => Error::AeSessionInvalid,
            sgx_status_t::SGX_ERROR_BUSY => Error::Busy,
            sgx_status_t::SGX_ERROR_MC_NOT_FOUND => Error::McNotFound,
            sgx_status_t::SGX_ERROR_MC_NO_ACCESS_RIGHT => Error::McNoAccessRight,
            sgx_status_t::SGX_ERROR_MC_USED_UP => Error::McUsedUp,
            sgx_status_t::SGX_ERROR_MC_OVER_QUOTA => Error::McOverQuota,
            sgx_status_t::SGX_ERROR_KDF_MISMATCH => Error::KdfMismatch,
            sgx_status_t::SGX_ERROR_UNRECOGNIZED_PLATFORM => Error::UnrecognizedPlatform,
            sgx_status_t::SGX_ERROR_UNSUPPORTED_CONFIG => Error::UnsupportedConfig,

            // 0x5000 - 0x5fff: AESM-internal errors
            sgx_status_t::SGX_ERROR_NO_PRIVILEGE => Error::NoPrivilege,

            // 0x6000 - 0x6fff: Encrypted Enclaves
            sgx_status_t::SGX_ERROR_PCL_ENCRYPTED => Error::PclEncrypted,
            sgx_status_t::SGX_ERROR_PCL_NOT_ENCRYPTED => Error::PclNotEncrypted,
            sgx_status_t::SGX_ERROR_PCL_MAC_MISMATCH => Error::PclMacMismatch,
            sgx_status_t::SGX_ERROR_PCL_SHA_MISMATCH => Error::PclShaMismatch,
            sgx_status_t::SGX_ERROR_PCL_GUID_MISMATCH => Error::PclGuidMismatch,

            // 0x7000 - 0x7fff: SGX Encrypted FS
            sgx_status_t::SGX_ERROR_FILE_BAD_STATUS => Error::FileBadStatus,
            sgx_status_t::SGX_ERROR_FILE_NO_KEY_ID => Error::FileNoKeyId,
            sgx_status_t::SGX_ERROR_FILE_NAME_MISMATCH => Error::FileNameMismatch,
            sgx_status_t::SGX_ERROR_FILE_NOT_SGX_FILE => Error::FileNotSgxFile,
            sgx_status_t::SGX_ERROR_FILE_CANT_OPEN_RECOVERY_FILE => Error::FileCantOpenRecoveryFile,
            sgx_status_t::SGX_ERROR_FILE_CANT_WRITE_RECOVERY_FILE => {
                Error::FileCantWriteRecoveryFile
            }
            sgx_status_t::SGX_ERROR_FILE_RECOVERY_NEEDED => Error::FileRecoveryNeeded,
            sgx_status_t::SGX_ERROR_FILE_FLUSH_FAILED => Error::FileFlushFailed,
            sgx_status_t::SGX_ERROR_FILE_CLOSE_FAILED => Error::FileCloseFailed,

            // 0x8000-0x8fff: Custom Attestation support
            sgx_status_t::SGX_ERROR_UNSUPPORTED_ATT_KEY_ID => Error::UnsupportedAttKeyId,
            sgx_status_t::SGX_ERROR_ATT_KEY_CERTIFICATION_FAILURE => {
                Error::AttKeyCertificationFailure
            }
            sgx_status_t::SGX_ERROR_ATT_KEY_UNINITIALIZED => Error::AttKeyUninitialized,
            sgx_status_t::SGX_ERROR_INVALID_ATT_KEY_CERT_DATA => Error::InvalidAttKeyCertData,
            sgx_status_t::SGX_ERROR_PLATFORM_CERT_UNAVAILABLE => Error::PlatformCertUnavailable,

            // 0xf000-0xffff: Internal-to-SGX errors
            sgx_status_t::SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED => {
                Error::EnclaveCreateInterrupted
            }

            // Map all unknowns to the unexpected error
            _ => Error::Unexpected,
        }
    }
}

#[cfg(test)]
mod test {
    use yare::parameterized;
    extern crate std;
    use super::*;

    #[parameterized(
    unexpected = { sgx_status_t::SGX_ERROR_UNEXPECTED, Error::Unexpected },
    memory_map = { sgx_status_t::SGX_ERROR_MEMORY_MAP_FAILURE, Error::MemoryMapFailure },
    invalid_function = { sgx_status_t::SGX_ERROR_INVALID_FUNCTION, Error::InvalidFunction },
    stack_overrun = { sgx_status_t::SGX_ERROR_STACK_OVERRUN, Error::StackOverrun },
    undefined_symbol = { sgx_status_t::SGX_ERROR_UNDEFINED_SYMBOL, Error::UndefinedSymbol },
    invalid_launch_token = { sgx_status_t::SGX_ERROR_INVALID_LAUNCH_TOKEN, Error::InvalidLaunchToken },
    mac_mismatch = { sgx_status_t::SGX_ERROR_MAC_MISMATCH, Error::MacMismatch },
    invalid_keyname = { sgx_status_t::SGX_ERROR_INVALID_KEYNAME, Error::InvalidKeyname },
    service_unavailable = { sgx_status_t::SGX_ERROR_SERVICE_UNAVAILABLE, Error::ServiceUnavailable },
    unsupported_config = { sgx_status_t::SGX_ERROR_UNSUPPORTED_CONFIG, Error::UnsupportedConfig },
    no_privilege = { sgx_status_t::SGX_ERROR_NO_PRIVILEGE, Error::NoPrivilege },
    pcl_encrypted = { sgx_status_t::SGX_ERROR_PCL_ENCRYPTED, Error::PclEncrypted },
    pcl_guid_mismatch = { sgx_status_t::SGX_ERROR_PCL_GUID_MISMATCH, Error::PclGuidMismatch },
    file_bad_status = { sgx_status_t::SGX_ERROR_FILE_BAD_STATUS, Error::FileBadStatus },
    file_close_failed = { sgx_status_t::SGX_ERROR_FILE_CLOSE_FAILED, Error::FileCloseFailed },
    unsupported_att_key_id = { sgx_status_t::SGX_ERROR_UNSUPPORTED_ATT_KEY_ID, Error::UnsupportedAttKeyId },
    platform_cert_unavailable = { sgx_status_t::SGX_ERROR_PLATFORM_CERT_UNAVAILABLE, Error::PlatformCertUnavailable },
    interrupted = { sgx_status_t::SGX_INTERNAL_ERROR_ENCLAVE_CREATE_INTERRUPTED, Error::EnclaveCreateInterrupted },
    )]
    fn from_sgx_to_error(sgx_status: sgx_status_t, expected: Error) {
        let error: Error = sgx_status.into();
        assert_eq!(error, expected);
    }

    #[test]
    fn unknown_sgx_error_maps_to_unexpected() {
        let unknown = sgx_status_t(0x8000);
        let error: Error = unknown.into();
        assert_eq!(error, Error::Unexpected);
    }
}
