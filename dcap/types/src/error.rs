// Copyright (c) 2022 The MobileCoin Foundation

//! This module provides the error type related to Quote v3

use displaydoc::Display;
use mc_sgx_dcap_sys_types::quote3_error_t;
use mc_sgx_util::{ResultFrom, ResultInto};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// An enumeration of errors which occur when using QuoteLib-related methods.
///
/// These errors correspond to error elements of
/// [`quote3_error_t`](mc_sgx_dcap_sys_types::quote3_error_t).
#[derive(Copy, Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[non_exhaustive]
#[repr(u32)]
pub enum Error {
    /// An unexpected internal error occurred
    Unexpected = quote3_error_t::SGX_QL_ERROR_UNEXPECTED.0,
    /// One of the parameters passed to an SGX FFI method was invalid
    InvalidParameter = quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER.0,
    /// Not enough memory is available to complete this operation
    OutOfMemory = quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY.0,
    /// Expected ECDSA_ID does not match the value stored in the ECDSA Blob
    EcdsaIdMismatch = quote3_error_t::SGX_QL_ERROR_ECDSA_ID_MISMATCH.0,
    /// The ECDSA blob pathname is too large
    PathnameBufferOverflow = quote3_error_t::SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR.0,
    /// Error accessing ECDSA blob
    FileAccess = quote3_error_t::SGX_QL_FILE_ACCESS_ERROR.0,
    /// Cached ECDSA key is invalid
    StoredKey = quote3_error_t::SGX_QL_ERROR_STORED_KEY.0,
    /// Cached ECDSA key does not match requested key
    PubKeyIdMismatch = quote3_error_t::SGX_QL_ERROR_PUB_KEY_ID_MISMATCH.0,
    /// PCE use the incorrect signature scheme
    InvalidPceSigScheme = quote3_error_t::SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME.0,
    /// There is a problem with the attestation key blob
    AttestationKeyBlob = quote3_error_t::SGX_QL_ATT_KEY_BLOB_ERROR.0,
    /// Unsupported attestation key ID
    UnsupportedAttestationKeyId = quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID.0,
    /// Unsupported enclave loading policy
    UnsupportedLoadingPolicy = quote3_error_t::SGX_QL_UNSUPPORTED_LOADING_POLICY.0,
    /// Unable to load the QE enclave
    InterfaceUnavailable = quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE.0,
    /// Unable to find the platform library with the dependent APIs (not fatal)
    PlatformLibUnavailable = quote3_error_t::SGX_QL_PLATFORM_LIB_UNAVAILABLE.0,
    /// The attestation key doesn't exist or has not been certified
    AttestationKeyNotInitialized = quote3_error_t::SGX_QL_ATT_KEY_NOT_INITIALIZED.0,
    /// The certification data retrieved from the platform library is invalid
    InvalidCertDataInAttestationKey = quote3_error_t::SGX_QL_ATT_KEY_CERT_DATA_INVALID.0,
    /// The platform library doesn't have any platform certification data
    NoPlatformCertData = quote3_error_t::SGX_QL_NO_PLATFORM_CERT_DATA.0,
    /// Not enough memory in the EPC to load the enclave
    OutOfEpc = quote3_error_t::SGX_QL_OUT_OF_EPC.0,
    /// There was a problem verifying an SGX REPORT.
    Report = quote3_error_t::SGX_QL_ERROR_REPORT.0,
    /// Interfacing to the enclave failed due to a power transition.
    EnclaveLost = quote3_error_t::SGX_QL_ENCLAVE_LOST.0,
    /// Error verifying the application enclave's report.
    InvalidReport = quote3_error_t::SGX_QL_INVALID_REPORT.0,
    /**
     * Unable to load the enclaves. Could be due to file I/O error, loading
     * infrastructure error, or non-SGX capable system
     */
    EnclaveLoad = quote3_error_t::SGX_QL_ENCLAVE_LOAD_ERROR.0,
    /**
     * The QE was unable to generate its own report targeting the
     * application enclave either because the QE doesn't support this
     * feature there is an enclave compatibility issue.
     *
     * Please call again with the p_qe_report_info to NULL.
     */
    UnableToGenerateQeReport = quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_QE_REPORT.0,
    /// Caused when the provider library returns an invalid TCB (too high).
    KeyCertification = quote3_error_t::SGX_QL_KEY_CERTIFCATION_ERROR.0,
    /// Network error when retrieving PCK certs
    Network = quote3_error_t::SGX_QL_NETWORK_ERROR.0,
    /// Message error when retrieving PCK certs
    Message = quote3_error_t::SGX_QL_MESSAGE_ERROR.0,
    /**
     * The platform does not have the quote verification collateral data
     * available.
     */
    NoQuoteCollateralData = quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA.0,
    /**
     * The quote verifier doesn’t support the certification data in the
     * Quote, the Intel QVE only supported CertType = 5
     */
    UnsupportedQuoteCertificationData =
        quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED.0,
    /**
     * The inputted quote format is not supported, either because the header
     * information is not supported or the quote is malformed in some way
     */
    UnsupportedQuoteFormat = quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED.0,
    /**
     * The QVE was unable to generate its own report targeting the
     * application enclave because there is an enclave compatibility
     * issue
     */
    UnableToGenerateReport = quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT.0,
    /// The signature over the QE Report is invalid
    InvalidQeReportSignature = quote3_error_t::SGX_QL_QE_REPORT_INVALID_SIGNATURE.0,
    /**
     * The quote verifier doesn’t support the format of the application
     * REPORT the Quote
     */
    UnsupportedQeReportFormat = quote3_error_t::SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT.0,
    /// The format of the PCK certificate is unsupported
    UnsupportedPckCertFormat = quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT.0,
    /**
     * There was an error verifying the PCK certificate signature chain
     * (including PCK certificate revocation)
     */
    PckCertChain = quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR.0,
    /// The format of the TCBInfo structure is unsupported
    UnsupportedTcbInfoFormat = quote3_error_t::SGX_QL_TCBINFO_UNSUPPORTED_FORMAT.0,
    /**
     * PCK Cert Family-Model-Stepping-Platform Custom SKU does not match the
     * TCBInfo Family-Model-Stepping-Platform Custom SKU
     */
    TcbInfoMismatch = quote3_error_t::SGX_QL_TCBINFO_MISMATCH.0,
    /// The format of the QEIdentity structure is unsupported
    UnsupportedQeIdentityFormat = quote3_error_t::SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT.0,
    /// The Quote’s QE doesn’t match the inputted expected QEIdentity
    QeIdentityMismatch = quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH.0,
    /// The TCB is out of date
    TcbOutOfDate = quote3_error_t::SGX_QL_TCB_OUT_OF_DATE.0,
    /// The TCB is out of date and configuration is needed
    TcbOutOfDateAndConfigurationNeeded =
        quote3_error_t::SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED.0,
    /// ?
    EnclaveIdentityOutOfDate = quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE.0,
    /// ?
    EnclaveReportIsvSvnOutOfDate = quote3_error_t::SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE.0,
    /// ?
    QeIdentityOutOfDate = quote3_error_t::SGX_QL_QE_IDENTITY_OUT_OF_DATE.0,
    /// ?
    TcbInfoExpired = quote3_error_t::SGX_QL_SGX_TCB_INFO_EXPIRED.0,
    /// The PCK certificate chain contains an expired certificate
    SgxPckCertChainExpired = quote3_error_t::SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED.0,
    /// The certificate revocation list has expired
    SgxCrlExpired = quote3_error_t::SGX_QL_SGX_CRL_EXPIRED.0,
    /// ?
    SgxSigningCertChainExpired = quote3_error_t::SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED.0,
    /// ?
    SgxEnclaveIdentityExpired = quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED.0,
    /// ?
    PckRevoked = quote3_error_t::SGX_QL_PCK_REVOKED.0,
    /// ?
    TcbRevoked = quote3_error_t::SGX_QL_TCB_REVOKED.0,
    /// ?
    TcbConfigurationNeeded = quote3_error_t::SGX_QL_TCB_CONFIGURATION_NEEDED.0,
    /// ?
    UnableToGetCollateral = quote3_error_t::SGX_QL_UNABLE_TO_GET_COLLATERAL.0,
    /// No enough privilege to perform the operation
    InvalidPrivilege = quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE.0,
    /// The platform does not have the QVE identity data available.
    NoQveIdentityData = quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA.0,
    /// ?
    UnsupportedCrlFormat = quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT.0,
    /// ?
    QeIdentityChainError = quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR.0,
    /// ?
    TcbInfoChainError = quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR.0,
    /// QvE returned supplemental data version mismatched between QVL and QvE
    QvlQveMismatch = quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH.0,
    /// TCB up to date but SW Hardening needed
    TcbSwHardeningNeeded = quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED.0,
    /// TCB up to date but Configuration and SW Hardening needed
    TcbConfigurationAndSwHardeningNeeded =
        quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED.0,
    /**
     * The platform has been configured to use the out-of-process
     * implementation of quote generation
     */
    UnsupportedMode = quote3_error_t::SGX_QL_UNSUPPORTED_MODE.0,
    /**
     * Can't open SGX device (this error happens only when running in
     * out-of-process mode)
     */
    NoDevice = quote3_error_t::SGX_QL_NO_DEVICE.0,
    /**
     * AESM didn't respond or the requested service is not supported (this
     * error happens only when running in out-of-process mode)
     */
    ServiceUnavailable = quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE.0,
    /**
     * Network connection or proxy setting issue is encountered (this error
     * happens only when running in out-of-process mode)
     */
    NetworkFailure = quote3_error_t::SGX_QL_NETWORK_FAILURE.0,
    /**
     * The request to out-of-process service has timed out (this error
     * happens only when running in out-of-process mode
     */
    ServiceTimeout = quote3_error_t::SGX_QL_SERVICE_TIMEOUT.0,
    /**
     * The requested service is temporarily not available (this error
     * happens only when running in out-of-process mode)
     */
    Busy = quote3_error_t::SGX_QL_ERROR_BUSY.0,
    /// Unexpected error from the cache service
    UnknownMessageResponse = quote3_error_t::SGX_QL_UNKNOWN_MESSAGE_RESPONSE.0,
    /// Error storing the retrieved cached data in persistent memory
    PersistentStorage = quote3_error_t::SGX_QL_PERSISTENT_STORAGE_ERROR.0,
    /// Message parsing error
    MessageParsing = quote3_error_t::SGX_QL_ERROR_MESSAGE_PARSING_ERROR.0,
    /// Platform was not found in the cache
    PlatformUnknown = quote3_error_t::SGX_QL_PLATFORM_UNKNOWN.0,
    /// The current PCS API version configured is unknown
    UnknownApiVersion = quote3_error_t::SGX_QL_UNKNOWN_API_VERSION.0,
    /// Certificates are not available for this platform
    CertsUnavailable = quote3_error_t::SGX_QL_CERTS_UNAVAILABLE.0,
    /// QvE Identity is NOT match to Intel signed QvE identity
    QveIdentityMismatch = quote3_error_t::SGX_QL_QVEIDENTITY_MISMATCH.0,
    /**
     * QvE ISVSVN is smaller than the ISVSVN threshold, or input QvE ISVSVN
     * is too small
     */
    QveOutOfDate = quote3_error_t::SGX_QL_QVE_OUT_OF_DATE.0,
    /// SGX PSW library cannot be loaded, could be due to file I/O error
    PswNotAvailable = quote3_error_t::SGX_QL_PSW_NOT_AVAILABLE.0,
    /// SGX quote verification collateral version not supported by QVL/QvE
    CollateralVersionNotSupported = quote3_error_t::SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED.0,
    /// TDX SEAM module identity is NOT match to Intel signed TDX SEAM module
    TdxModuleMismatch = quote3_error_t::SGX_QL_TDX_MODULE_MISMATCH.0,
    /// Indicate max error to allow better translation
    Max = quote3_error_t::SGX_QL_ERROR_MAX.0,
}

impl TryFrom<quote3_error_t> for Error {
    type Error = ();

    fn try_from(value: quote3_error_t) -> Result<Self, Self::Error> {
        match value {
            quote3_error_t::SGX_QL_SUCCESS => Err(()),

            quote3_error_t::SGX_QL_ERROR_UNEXPECTED => Ok(Error::Unexpected),
            quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER => Ok(Error::InvalidParameter),
            quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY => Ok(Error::OutOfMemory),
            quote3_error_t::SGX_QL_ERROR_ECDSA_ID_MISMATCH => Ok(Error::EcdsaIdMismatch),
            quote3_error_t::SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR => {
                Ok(Error::PathnameBufferOverflow)
            }
            quote3_error_t::SGX_QL_FILE_ACCESS_ERROR => Ok(Error::FileAccess),
            quote3_error_t::SGX_QL_ERROR_STORED_KEY => Ok(Error::StoredKey),
            quote3_error_t::SGX_QL_ERROR_PUB_KEY_ID_MISMATCH => Ok(Error::PubKeyIdMismatch),
            quote3_error_t::SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME => Ok(Error::InvalidPceSigScheme),
            quote3_error_t::SGX_QL_ATT_KEY_BLOB_ERROR => Ok(Error::AttestationKeyBlob),
            quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID => Ok(Error::UnsupportedAttestationKeyId),
            quote3_error_t::SGX_QL_UNSUPPORTED_LOADING_POLICY => {
                Ok(Error::UnsupportedLoadingPolicy)
            }
            quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE => Ok(Error::InterfaceUnavailable),
            quote3_error_t::SGX_QL_PLATFORM_LIB_UNAVAILABLE => Ok(Error::PlatformLibUnavailable),
            quote3_error_t::SGX_QL_ATT_KEY_NOT_INITIALIZED => {
                Ok(Error::AttestationKeyNotInitialized)
            }
            quote3_error_t::SGX_QL_ATT_KEY_CERT_DATA_INVALID => {
                Ok(Error::InvalidCertDataInAttestationKey)
            }
            quote3_error_t::SGX_QL_NO_PLATFORM_CERT_DATA => Ok(Error::NoPlatformCertData),
            quote3_error_t::SGX_QL_OUT_OF_EPC => Ok(Error::OutOfEpc),
            quote3_error_t::SGX_QL_ERROR_REPORT => Ok(Error::Report),
            quote3_error_t::SGX_QL_ENCLAVE_LOST => Ok(Error::EnclaveLost),
            quote3_error_t::SGX_QL_INVALID_REPORT => Ok(Error::InvalidReport),
            quote3_error_t::SGX_QL_ENCLAVE_LOAD_ERROR => Ok(Error::EnclaveLoad),
            quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_QE_REPORT => {
                Ok(Error::UnableToGenerateQeReport)
            }
            quote3_error_t::SGX_QL_KEY_CERTIFCATION_ERROR => Ok(Error::KeyCertification),
            quote3_error_t::SGX_QL_NETWORK_ERROR => Ok(Error::Network),
            quote3_error_t::SGX_QL_MESSAGE_ERROR => Ok(Error::Message),
            quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA => Ok(Error::NoQuoteCollateralData),
            quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED => {
                Ok(Error::UnsupportedQuoteCertificationData)
            }
            quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED => Ok(Error::UnsupportedQuoteFormat),
            quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT => Ok(Error::UnableToGenerateReport),
            quote3_error_t::SGX_QL_QE_REPORT_INVALID_SIGNATURE => {
                Ok(Error::InvalidQeReportSignature)
            }
            quote3_error_t::SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT => {
                Ok(Error::UnsupportedQeReportFormat)
            }
            quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT => {
                Ok(Error::UnsupportedPckCertFormat)
            }
            quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR => Ok(Error::PckCertChain),
            quote3_error_t::SGX_QL_TCBINFO_UNSUPPORTED_FORMAT => {
                Ok(Error::UnsupportedTcbInfoFormat)
            }
            quote3_error_t::SGX_QL_TCBINFO_MISMATCH => Ok(Error::TcbInfoMismatch),
            quote3_error_t::SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT => {
                Ok(Error::UnsupportedQeIdentityFormat)
            }
            quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH => Ok(Error::QeIdentityMismatch),
            quote3_error_t::SGX_QL_TCB_OUT_OF_DATE => Ok(Error::TcbOutOfDate),
            quote3_error_t::SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED => {
                Ok(Error::TcbOutOfDateAndConfigurationNeeded)
            }
            quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE => {
                Ok(Error::EnclaveIdentityOutOfDate)
            }
            quote3_error_t::SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE => {
                Ok(Error::EnclaveReportIsvSvnOutOfDate)
            }
            quote3_error_t::SGX_QL_QE_IDENTITY_OUT_OF_DATE => Ok(Error::QeIdentityOutOfDate),
            quote3_error_t::SGX_QL_SGX_TCB_INFO_EXPIRED => Ok(Error::TcbInfoExpired),
            quote3_error_t::SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED => Ok(Error::SgxPckCertChainExpired),
            quote3_error_t::SGX_QL_SGX_CRL_EXPIRED => Ok(Error::SgxCrlExpired),
            quote3_error_t::SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED => {
                Ok(Error::SgxSigningCertChainExpired)
            }
            quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED => {
                Ok(Error::SgxEnclaveIdentityExpired)
            }
            quote3_error_t::SGX_QL_PCK_REVOKED => Ok(Error::PckRevoked),
            quote3_error_t::SGX_QL_TCB_REVOKED => Ok(Error::TcbRevoked),
            quote3_error_t::SGX_QL_TCB_CONFIGURATION_NEEDED => Ok(Error::TcbConfigurationNeeded),
            quote3_error_t::SGX_QL_UNABLE_TO_GET_COLLATERAL => Ok(Error::UnableToGetCollateral),
            quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE => Ok(Error::InvalidPrivilege),
            quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA => Ok(Error::NoQveIdentityData),
            quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT => Ok(Error::UnsupportedCrlFormat),
            quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR => Ok(Error::QeIdentityChainError),
            quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR => Ok(Error::TcbInfoChainError),
            quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH => Ok(Error::QvlQveMismatch),
            quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED => Ok(Error::TcbSwHardeningNeeded),
            quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED => {
                Ok(Error::TcbConfigurationAndSwHardeningNeeded)
            }
            quote3_error_t::SGX_QL_UNSUPPORTED_MODE => Ok(Error::UnsupportedMode),
            quote3_error_t::SGX_QL_NO_DEVICE => Ok(Error::NoDevice),
            quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE => Ok(Error::ServiceUnavailable),
            quote3_error_t::SGX_QL_NETWORK_FAILURE => Ok(Error::NetworkFailure),
            quote3_error_t::SGX_QL_SERVICE_TIMEOUT => Ok(Error::ServiceTimeout),
            quote3_error_t::SGX_QL_ERROR_BUSY => Ok(Error::Busy),
            quote3_error_t::SGX_QL_UNKNOWN_MESSAGE_RESPONSE => Ok(Error::UnknownMessageResponse),
            quote3_error_t::SGX_QL_PERSISTENT_STORAGE_ERROR => Ok(Error::PersistentStorage),
            quote3_error_t::SGX_QL_ERROR_MESSAGE_PARSING_ERROR => Ok(Error::MessageParsing),
            quote3_error_t::SGX_QL_PLATFORM_UNKNOWN => Ok(Error::PlatformUnknown),
            quote3_error_t::SGX_QL_UNKNOWN_API_VERSION => Ok(Error::UnknownApiVersion),
            quote3_error_t::SGX_QL_CERTS_UNAVAILABLE => Ok(Error::CertsUnavailable),
            quote3_error_t::SGX_QL_QVEIDENTITY_MISMATCH => Ok(Error::QveIdentityMismatch),
            quote3_error_t::SGX_QL_QVE_OUT_OF_DATE => Ok(Error::QveOutOfDate),
            quote3_error_t::SGX_QL_PSW_NOT_AVAILABLE => Ok(Error::PswNotAvailable),
            quote3_error_t::SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED => {
                Ok(Error::CollateralVersionNotSupported)
            }
            quote3_error_t::SGX_QL_TDX_MODULE_MISMATCH => Ok(Error::TdxModuleMismatch),
            quote3_error_t::SGX_QL_ERROR_MAX => Ok(Error::Max),
            // Map all unknowns to the unexpected error
            _ => Ok(Error::Unexpected),
        }
    }
}

impl From<Error> for quote3_error_t {
    fn from(src: Error) -> quote3_error_t {
        quote3_error_t(src as u32)
    }
}

impl ResultFrom<quote3_error_t> for Error {}
impl ResultInto<Error> for quote3_error_t {}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use yare::parameterized;

    #[parameterized(
    unexpected = { quote3_error_t::SGX_QL_ERROR_UNEXPECTED, Error::Unexpected },
    invalid_parameter = { quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER, Error::InvalidParameter },
    out_of_memory = { quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY, Error::OutOfMemory },
    ecdsa_id_mismatch = { quote3_error_t::SGX_QL_ERROR_ECDSA_ID_MISMATCH, Error::EcdsaIdMismatch },
    pathname_buffer_overflow = { quote3_error_t::SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR, Error::PathnameBufferOverflow },
    file_access = { quote3_error_t::SGX_QL_FILE_ACCESS_ERROR, Error::FileAccess },
    stored_key = { quote3_error_t::SGX_QL_ERROR_STORED_KEY, Error::StoredKey },
    pub_key_id_mismatch = { quote3_error_t::SGX_QL_ERROR_PUB_KEY_ID_MISMATCH, Error::PubKeyIdMismatch },
    invalid_pce_sig_scheme = { quote3_error_t::SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME, Error::InvalidPceSigScheme },
    attestation_key_blob = { quote3_error_t::SGX_QL_ATT_KEY_BLOB_ERROR, Error::AttestationKeyBlob },
    unsupported_att_key_id = { quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID, Error::UnsupportedAttestationKeyId },
    unsupported_loading_policy = { quote3_error_t::SGX_QL_UNSUPPORTED_LOADING_POLICY, Error::UnsupportedLoadingPolicy },
    interface_unavailable = { quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE, Error::InterfaceUnavailable },
    platform_lib_unavailable = { quote3_error_t::SGX_QL_PLATFORM_LIB_UNAVAILABLE, Error::PlatformLibUnavailable },
    attestation_key_not_initialized = { quote3_error_t::SGX_QL_ATT_KEY_NOT_INITIALIZED, Error::AttestationKeyNotInitialized },
    invalid_cert_data_in_attestation_key = { quote3_error_t::SGX_QL_ATT_KEY_CERT_DATA_INVALID, Error::InvalidCertDataInAttestationKey },
    no_platform_cert_data = { quote3_error_t::SGX_QL_NO_PLATFORM_CERT_DATA, Error::NoPlatformCertData },
    out_of_epc = { quote3_error_t::SGX_QL_OUT_OF_EPC, Error::OutOfEpc },
    report = { quote3_error_t::SGX_QL_ERROR_REPORT, Error::Report },
    enclave_lost = { quote3_error_t::SGX_QL_ENCLAVE_LOST, Error::EnclaveLost },
    invalid_report = { quote3_error_t::SGX_QL_INVALID_REPORT, Error::InvalidReport },
    enclave_load = { quote3_error_t::SGX_QL_ENCLAVE_LOAD_ERROR, Error::EnclaveLoad },
    unable_to_generate_qe_report = { quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_QE_REPORT, Error::UnableToGenerateQeReport },
    key_certification = { quote3_error_t::SGX_QL_KEY_CERTIFCATION_ERROR, Error::KeyCertification },
    network = { quote3_error_t::SGX_QL_NETWORK_ERROR, Error::Network },
    message = { quote3_error_t::SGX_QL_MESSAGE_ERROR, Error::Message },
    no_quote_collateral_data = { quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA, Error::NoQuoteCollateralData },
    unsupported_quote_certification_data = { quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED, Error::UnsupportedQuoteCertificationData },
    unsupported_quote_format = { quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED, Error::UnsupportedQuoteFormat },
    unable_to_generate_report = { quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT, Error::UnableToGenerateReport },
    invalid_qe_report_signature = { quote3_error_t::SGX_QL_QE_REPORT_INVALID_SIGNATURE, Error::InvalidQeReportSignature },
    unsupported_qe_report_format = { quote3_error_t::SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT, Error::UnsupportedQeReportFormat },
    unsupported_pck_cert_format = { quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT, Error::UnsupportedPckCertFormat },
    pck_cert_chain = { quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR, Error::PckCertChain },
    unsupported_tcb_info_format = { quote3_error_t::SGX_QL_TCBINFO_UNSUPPORTED_FORMAT, Error::UnsupportedTcbInfoFormat },
    tcb_info_mismatch = { quote3_error_t::SGX_QL_TCBINFO_MISMATCH, Error::TcbInfoMismatch },
    unsupported_qe_identity_format = { quote3_error_t::SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT, Error::UnsupportedQeIdentityFormat },
    qe_identity_mismatch = { quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH, Error::QeIdentityMismatch },
    tcb_out_of_date = { quote3_error_t::SGX_QL_TCB_OUT_OF_DATE, Error::TcbOutOfDate },
    tcb_out_of_date_and_configuration_needed = { quote3_error_t::SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED, Error::TcbOutOfDateAndConfigurationNeeded },
    enclave_identity_out_of_date = { quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE, Error::EnclaveIdentityOutOfDate },
    enclave_report_isvsvn_out_of_date = { quote3_error_t::SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE, Error::EnclaveReportIsvSvnOutOfDate },
    qe_identity_out_of_date = { quote3_error_t::SGX_QL_QE_IDENTITY_OUT_OF_DATE, Error::QeIdentityOutOfDate },
    tcb_info_expired = { quote3_error_t::SGX_QL_SGX_TCB_INFO_EXPIRED, Error::TcbInfoExpired },
    sgx_pck_cert_chain_expired = { quote3_error_t::SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED, Error::SgxPckCertChainExpired },
    sgx_crl_expired = { quote3_error_t::SGX_QL_SGX_CRL_EXPIRED, Error::SgxCrlExpired },
    sgx_signing_cert_chain_expired = { quote3_error_t::SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED, Error::SgxSigningCertChainExpired },
    sgx_enclave_identity_expired = { quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED, Error::SgxEnclaveIdentityExpired },
    pck_revoked = { quote3_error_t::SGX_QL_PCK_REVOKED, Error::PckRevoked },
    tcb_revoked = { quote3_error_t::SGX_QL_TCB_REVOKED, Error::TcbRevoked },
    tcb_configuration_needed = { quote3_error_t::SGX_QL_TCB_CONFIGURATION_NEEDED, Error::TcbConfigurationNeeded },
    unable_to_get_collateral = { quote3_error_t::SGX_QL_UNABLE_TO_GET_COLLATERAL, Error::UnableToGetCollateral },
    invalid_privilege = { quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE, Error::InvalidPrivilege },
    no_qve_identity_data = { quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA, Error::NoQveIdentityData },
    unsupported_crl_format = { quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT, Error::UnsupportedCrlFormat },
    qe_identity_chain_error = { quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR, Error::QeIdentityChainError },
    tcb_info_chain_error = { quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR, Error::TcbInfoChainError },
    qvl_qve_mismatch = { quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH, Error::QvlQveMismatch },
    tcb_sw_hardening_needed = { quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED, Error::TcbSwHardeningNeeded },
    tcb_configuration_and_sw_hardening_needed = { quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED, Error::TcbConfigurationAndSwHardeningNeeded },
    unsupported_mode = { quote3_error_t::SGX_QL_UNSUPPORTED_MODE, Error::UnsupportedMode },
    no_device = { quote3_error_t::SGX_QL_NO_DEVICE, Error::NoDevice },
    service_unavailable = { quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE, Error::ServiceUnavailable },
    network_failure = { quote3_error_t::SGX_QL_NETWORK_FAILURE, Error::NetworkFailure },
    service_timeout = { quote3_error_t::SGX_QL_SERVICE_TIMEOUT, Error::ServiceTimeout },
    busy = { quote3_error_t::SGX_QL_ERROR_BUSY, Error::Busy },
    unknown_message_response = { quote3_error_t::SGX_QL_UNKNOWN_MESSAGE_RESPONSE, Error::UnknownMessageResponse },
    persistent_storage = { quote3_error_t::SGX_QL_PERSISTENT_STORAGE_ERROR, Error::PersistentStorage },
    message_parsing = { quote3_error_t::SGX_QL_ERROR_MESSAGE_PARSING_ERROR, Error::MessageParsing },
    platform_unknown = { quote3_error_t::SGX_QL_PLATFORM_UNKNOWN, Error::PlatformUnknown },
    unknown_api_version = { quote3_error_t::SGX_QL_UNKNOWN_API_VERSION, Error::UnknownApiVersion },
    certs_unavailable = { quote3_error_t::SGX_QL_CERTS_UNAVAILABLE, Error::CertsUnavailable },
    qve_identity_mismatch = { quote3_error_t::SGX_QL_QVEIDENTITY_MISMATCH, Error::QveIdentityMismatch },
    qve_out_of_date = { quote3_error_t::SGX_QL_QVE_OUT_OF_DATE, Error::QveOutOfDate },
    psw_not_available = { quote3_error_t::SGX_QL_PSW_NOT_AVAILABLE, Error::PswNotAvailable },
    collateral_version_not_supported = { quote3_error_t::SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED, Error::CollateralVersionNotSupported },
    tdx_module_mismatch = { quote3_error_t::SGX_QL_TDX_MODULE_MISMATCH, Error::TdxModuleMismatch },
    max = { quote3_error_t::SGX_QL_ERROR_MAX, Error::Max }
    )]
    fn error_from_ffi(ffi: quote3_error_t, expected: Error) {
        assert_eq!(
            expected,
            Error::try_from(ffi).expect("Could not create error from ffi type")
        )
    }

    #[test]
    fn success_is_not_an_error() {
        assert!(Error::try_from(quote3_error_t::SGX_QL_SUCCESS).is_err())
    }

    #[test]
    fn unknown_quote3_error_maps_to_unexpected() {
        let unknown = quote3_error_t(quote3_error_t::SGX_QL_ERROR_MAX.0 + 1);
        assert_eq!(
            Error::try_from(unknown).expect("Could not parse an unknown SGX Status"),
            Error::Unexpected
        );
    }
}
