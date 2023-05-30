// Copyright (c) 2022-2023 The MobileCoin Foundation

//! This module provides the error type related to Quote v3

use displaydoc::Display;
use mc_sgx_dcap_sys_types::quote3_error_t;
use mc_sgx_util::{ResultFrom, ResultInto};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Errors interacting with a Quote3
#[derive(Clone, Debug, Display, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Quote3Error {
    /** Quote buffer too small; actual size: {actual}, required size
     * {required} */
    #[allow(missing_docs)]
    InputLength { required: usize, actual: usize },
    /// Invalid quote version: {0}, should be: 3
    Version(u16),
    /// Failure to convert from bytes to ECDSA types
    Ecdsa,
    /// Invalid certification data type: {0}, should be 1 - 7
    CertificationDataType(u16),
    /// Error verifying the signature
    SignatureVerification,
}

impl Quote3Error {
    /// Increase any and all size values in the Error.
    /// Errors without a size field will be returned unmodified.  For example
    /// [`Quote3Error::Version`] will not be modified by this function even
    /// though it has a numeric value.
    pub(crate) fn increase_size(self, increase: usize) -> Self {
        match self {
            Self::InputLength { actual, required } => {
                let actual = actual + increase;
                let required = required + increase;
                Self::InputLength { actual, required }
            }
            // Intentionally no-op so one doesn't need to pre-evaluate.
            e => e,
        }
    }
}

impl From<p256::ecdsa::Error> for Quote3Error {
    fn from(_: p256::ecdsa::Error) -> Self {
        // ecdsa::Error is opaque, and only provides additional information via
        // `std::Error` impl.
        Quote3Error::Ecdsa
    }
}

/// An enumeration of errors which occur when using QuoteLib-related methods.
///
/// These errors correspond to error elements of
/// [`quote3_error_t`](mc_sgx_dcap_sys_types::quote3_error_t).
#[derive(Copy, Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[non_exhaustive]
#[repr(u32)]
pub enum QlError {
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
    /// QE identity was not found
    QeIdentityNotFound = quote3_error_t::SGX_QL_QEIDENTITY_NOT_FOUND.0,
    /// TCB Info was not found
    TcbInfoNotFound = quote3_error_t::SGX_QL_TCBINFO_NOT_FOUND.0,
    /// Internal server error
    InternalServerError = quote3_error_t::SGX_QL_INTERNAL_SERVER_ERROR.0,
    /// The supplemental data version is not supported
    SupplementalDataVersionNotSupported =
        quote3_error_t::SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED.0,
    /// The certificate used to establish SSL session is untrusted
    RootCaUntrusted = quote3_error_t::SGX_QL_ROOT_CA_UNTRUSTED.0,
    /// The current TCB level cannot be found in the platform/enclave TCB info
    TcbNotSupported = quote3_error_t::SGX_QL_TCB_NOT_SUPPORTED.0,

    /// Indicate max error to allow better translation
    Max = quote3_error_t::SGX_QL_ERROR_MAX.0,
}

impl TryFrom<quote3_error_t> for QlError {
    type Error = ();

    fn try_from(value: quote3_error_t) -> Result<Self, Self::Error> {
        match value {
            quote3_error_t::SGX_QL_SUCCESS => Err(()),

            quote3_error_t::SGX_QL_ERROR_UNEXPECTED => Ok(QlError::Unexpected),
            quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER => Ok(QlError::InvalidParameter),
            quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY => Ok(QlError::OutOfMemory),
            quote3_error_t::SGX_QL_ERROR_ECDSA_ID_MISMATCH => Ok(QlError::EcdsaIdMismatch),
            quote3_error_t::SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR => {
                Ok(QlError::PathnameBufferOverflow)
            }
            quote3_error_t::SGX_QL_FILE_ACCESS_ERROR => Ok(QlError::FileAccess),
            quote3_error_t::SGX_QL_ERROR_STORED_KEY => Ok(QlError::StoredKey),
            quote3_error_t::SGX_QL_ERROR_PUB_KEY_ID_MISMATCH => Ok(QlError::PubKeyIdMismatch),
            quote3_error_t::SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME => Ok(QlError::InvalidPceSigScheme),
            quote3_error_t::SGX_QL_ATT_KEY_BLOB_ERROR => Ok(QlError::AttestationKeyBlob),
            quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID => {
                Ok(QlError::UnsupportedAttestationKeyId)
            }
            quote3_error_t::SGX_QL_UNSUPPORTED_LOADING_POLICY => {
                Ok(QlError::UnsupportedLoadingPolicy)
            }
            quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE => Ok(QlError::InterfaceUnavailable),
            quote3_error_t::SGX_QL_PLATFORM_LIB_UNAVAILABLE => Ok(QlError::PlatformLibUnavailable),
            quote3_error_t::SGX_QL_ATT_KEY_NOT_INITIALIZED => {
                Ok(QlError::AttestationKeyNotInitialized)
            }
            quote3_error_t::SGX_QL_ATT_KEY_CERT_DATA_INVALID => {
                Ok(QlError::InvalidCertDataInAttestationKey)
            }
            quote3_error_t::SGX_QL_NO_PLATFORM_CERT_DATA => Ok(QlError::NoPlatformCertData),
            quote3_error_t::SGX_QL_OUT_OF_EPC => Ok(QlError::OutOfEpc),
            quote3_error_t::SGX_QL_ERROR_REPORT => Ok(QlError::Report),
            quote3_error_t::SGX_QL_ENCLAVE_LOST => Ok(QlError::EnclaveLost),
            quote3_error_t::SGX_QL_INVALID_REPORT => Ok(QlError::InvalidReport),
            quote3_error_t::SGX_QL_ENCLAVE_LOAD_ERROR => Ok(QlError::EnclaveLoad),
            quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_QE_REPORT => {
                Ok(QlError::UnableToGenerateQeReport)
            }
            quote3_error_t::SGX_QL_KEY_CERTIFCATION_ERROR => Ok(QlError::KeyCertification),
            quote3_error_t::SGX_QL_NETWORK_ERROR => Ok(QlError::Network),
            quote3_error_t::SGX_QL_MESSAGE_ERROR => Ok(QlError::Message),
            quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA => Ok(QlError::NoQuoteCollateralData),
            quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED => {
                Ok(QlError::UnsupportedQuoteCertificationData)
            }
            quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED => Ok(QlError::UnsupportedQuoteFormat),
            quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT => Ok(QlError::UnableToGenerateReport),
            quote3_error_t::SGX_QL_QE_REPORT_INVALID_SIGNATURE => {
                Ok(QlError::InvalidQeReportSignature)
            }
            quote3_error_t::SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT => {
                Ok(QlError::UnsupportedQeReportFormat)
            }
            quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT => {
                Ok(QlError::UnsupportedPckCertFormat)
            }
            quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR => Ok(QlError::PckCertChain),
            quote3_error_t::SGX_QL_TCBINFO_UNSUPPORTED_FORMAT => {
                Ok(QlError::UnsupportedTcbInfoFormat)
            }
            quote3_error_t::SGX_QL_TCBINFO_MISMATCH => Ok(QlError::TcbInfoMismatch),
            quote3_error_t::SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT => {
                Ok(QlError::UnsupportedQeIdentityFormat)
            }
            quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH => Ok(QlError::QeIdentityMismatch),
            quote3_error_t::SGX_QL_TCB_OUT_OF_DATE => Ok(QlError::TcbOutOfDate),
            quote3_error_t::SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED => {
                Ok(QlError::TcbOutOfDateAndConfigurationNeeded)
            }
            quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE => {
                Ok(QlError::EnclaveIdentityOutOfDate)
            }
            quote3_error_t::SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE => {
                Ok(QlError::EnclaveReportIsvSvnOutOfDate)
            }
            quote3_error_t::SGX_QL_QE_IDENTITY_OUT_OF_DATE => Ok(QlError::QeIdentityOutOfDate),
            quote3_error_t::SGX_QL_SGX_TCB_INFO_EXPIRED => Ok(QlError::TcbInfoExpired),
            quote3_error_t::SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED => {
                Ok(QlError::SgxPckCertChainExpired)
            }
            quote3_error_t::SGX_QL_SGX_CRL_EXPIRED => Ok(QlError::SgxCrlExpired),
            quote3_error_t::SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED => {
                Ok(QlError::SgxSigningCertChainExpired)
            }
            quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED => {
                Ok(QlError::SgxEnclaveIdentityExpired)
            }
            quote3_error_t::SGX_QL_PCK_REVOKED => Ok(QlError::PckRevoked),
            quote3_error_t::SGX_QL_TCB_REVOKED => Ok(QlError::TcbRevoked),
            quote3_error_t::SGX_QL_TCB_CONFIGURATION_NEEDED => Ok(QlError::TcbConfigurationNeeded),
            quote3_error_t::SGX_QL_UNABLE_TO_GET_COLLATERAL => Ok(QlError::UnableToGetCollateral),
            quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE => Ok(QlError::InvalidPrivilege),
            quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA => Ok(QlError::NoQveIdentityData),
            quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT => Ok(QlError::UnsupportedCrlFormat),
            quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR => Ok(QlError::QeIdentityChainError),
            quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR => Ok(QlError::TcbInfoChainError),
            quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH => Ok(QlError::QvlQveMismatch),
            quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED => Ok(QlError::TcbSwHardeningNeeded),
            quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED => {
                Ok(QlError::TcbConfigurationAndSwHardeningNeeded)
            }
            quote3_error_t::SGX_QL_UNSUPPORTED_MODE => Ok(QlError::UnsupportedMode),
            quote3_error_t::SGX_QL_NO_DEVICE => Ok(QlError::NoDevice),
            quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE => Ok(QlError::ServiceUnavailable),
            quote3_error_t::SGX_QL_NETWORK_FAILURE => Ok(QlError::NetworkFailure),
            quote3_error_t::SGX_QL_SERVICE_TIMEOUT => Ok(QlError::ServiceTimeout),
            quote3_error_t::SGX_QL_ERROR_BUSY => Ok(QlError::Busy),
            quote3_error_t::SGX_QL_UNKNOWN_MESSAGE_RESPONSE => Ok(QlError::UnknownMessageResponse),
            quote3_error_t::SGX_QL_PERSISTENT_STORAGE_ERROR => Ok(QlError::PersistentStorage),
            quote3_error_t::SGX_QL_ERROR_MESSAGE_PARSING_ERROR => Ok(QlError::MessageParsing),
            quote3_error_t::SGX_QL_PLATFORM_UNKNOWN => Ok(QlError::PlatformUnknown),
            quote3_error_t::SGX_QL_UNKNOWN_API_VERSION => Ok(QlError::UnknownApiVersion),
            quote3_error_t::SGX_QL_CERTS_UNAVAILABLE => Ok(QlError::CertsUnavailable),
            quote3_error_t::SGX_QL_QVEIDENTITY_MISMATCH => Ok(QlError::QveIdentityMismatch),
            quote3_error_t::SGX_QL_QVE_OUT_OF_DATE => Ok(QlError::QveOutOfDate),
            quote3_error_t::SGX_QL_PSW_NOT_AVAILABLE => Ok(QlError::PswNotAvailable),
            quote3_error_t::SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED => {
                Ok(QlError::CollateralVersionNotSupported)
            }
            quote3_error_t::SGX_QL_TDX_MODULE_MISMATCH => Ok(QlError::TdxModuleMismatch),
            quote3_error_t::SGX_QL_QEIDENTITY_NOT_FOUND => Ok(QlError::QeIdentityNotFound),
            quote3_error_t::SGX_QL_TCBINFO_NOT_FOUND => Ok(QlError::TcbInfoNotFound),
            quote3_error_t::SGX_QL_INTERNAL_SERVER_ERROR => Ok(QlError::InternalServerError),
            quote3_error_t::SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED => {
                Ok(QlError::SupplementalDataVersionNotSupported)
            }
            quote3_error_t::SGX_QL_ROOT_CA_UNTRUSTED => Ok(QlError::RootCaUntrusted),
            quote3_error_t::SGX_QL_TCB_NOT_SUPPORTED => Ok(QlError::TcbNotSupported),
            quote3_error_t::SGX_QL_ERROR_MAX => Ok(QlError::Max),
            // Map all unknowns to the unexpected error
            _ => Ok(QlError::Unexpected),
        }
    }
}

impl From<QlError> for quote3_error_t {
    fn from(src: QlError) -> quote3_error_t {
        quote3_error_t(src as u32)
    }
}

impl ResultFrom<quote3_error_t> for QlError {}
impl ResultInto<QlError> for quote3_error_t {}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use yare::parameterized;

    #[parameterized(
    unexpected = { quote3_error_t::SGX_QL_ERROR_UNEXPECTED, QlError::Unexpected },
    invalid_parameter = { quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER, QlError::InvalidParameter },
    out_of_memory = { quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY, QlError::OutOfMemory },
    ecdsa_id_mismatch = { quote3_error_t::SGX_QL_ERROR_ECDSA_ID_MISMATCH, QlError::EcdsaIdMismatch },
    pathname_buffer_overflow = { quote3_error_t::SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR, QlError::PathnameBufferOverflow },
    file_access = { quote3_error_t::SGX_QL_FILE_ACCESS_ERROR, QlError::FileAccess },
    stored_key = { quote3_error_t::SGX_QL_ERROR_STORED_KEY, QlError::StoredKey },
    pub_key_id_mismatch = { quote3_error_t::SGX_QL_ERROR_PUB_KEY_ID_MISMATCH, QlError::PubKeyIdMismatch },
    invalid_pce_sig_scheme = { quote3_error_t::SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME, QlError::InvalidPceSigScheme },
    attestation_key_blob = { quote3_error_t::SGX_QL_ATT_KEY_BLOB_ERROR, QlError::AttestationKeyBlob },
    unsupported_att_key_id = { quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID, QlError::UnsupportedAttestationKeyId },
    unsupported_loading_policy = { quote3_error_t::SGX_QL_UNSUPPORTED_LOADING_POLICY, QlError::UnsupportedLoadingPolicy },
    interface_unavailable = { quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE, QlError::InterfaceUnavailable },
    platform_lib_unavailable = { quote3_error_t::SGX_QL_PLATFORM_LIB_UNAVAILABLE, QlError::PlatformLibUnavailable },
    attestation_key_not_initialized = { quote3_error_t::SGX_QL_ATT_KEY_NOT_INITIALIZED, QlError::AttestationKeyNotInitialized },
    invalid_cert_data_in_attestation_key = { quote3_error_t::SGX_QL_ATT_KEY_CERT_DATA_INVALID, QlError::InvalidCertDataInAttestationKey },
    no_platform_cert_data = { quote3_error_t::SGX_QL_NO_PLATFORM_CERT_DATA, QlError::NoPlatformCertData },
    out_of_epc = { quote3_error_t::SGX_QL_OUT_OF_EPC, QlError::OutOfEpc },
    report = { quote3_error_t::SGX_QL_ERROR_REPORT, QlError::Report },
    enclave_lost = { quote3_error_t::SGX_QL_ENCLAVE_LOST, QlError::EnclaveLost },
    invalid_report = { quote3_error_t::SGX_QL_INVALID_REPORT, QlError::InvalidReport },
    enclave_load = { quote3_error_t::SGX_QL_ENCLAVE_LOAD_ERROR, QlError::EnclaveLoad },
    unable_to_generate_qe_report = { quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_QE_REPORT, QlError::UnableToGenerateQeReport },
    key_certification = { quote3_error_t::SGX_QL_KEY_CERTIFCATION_ERROR, QlError::KeyCertification },
    network = { quote3_error_t::SGX_QL_NETWORK_ERROR, QlError::Network },
    message = { quote3_error_t::SGX_QL_MESSAGE_ERROR, QlError::Message },
    no_quote_collateral_data = { quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA, QlError::NoQuoteCollateralData },
    unsupported_quote_certification_data = { quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED, QlError::UnsupportedQuoteCertificationData },
    unsupported_quote_format = { quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED, QlError::UnsupportedQuoteFormat },
    unable_to_generate_report = { quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT, QlError::UnableToGenerateReport },
    invalid_qe_report_signature = { quote3_error_t::SGX_QL_QE_REPORT_INVALID_SIGNATURE, QlError::InvalidQeReportSignature },
    unsupported_qe_report_format = { quote3_error_t::SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT, QlError::UnsupportedQeReportFormat },
    unsupported_pck_cert_format = { quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT, QlError::UnsupportedPckCertFormat },
    pck_cert_chain = { quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR, QlError::PckCertChain },
    unsupported_tcb_info_format = { quote3_error_t::SGX_QL_TCBINFO_UNSUPPORTED_FORMAT, QlError::UnsupportedTcbInfoFormat },
    tcb_info_mismatch = { quote3_error_t::SGX_QL_TCBINFO_MISMATCH, QlError::TcbInfoMismatch },
    unsupported_qe_identity_format = { quote3_error_t::SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT, QlError::UnsupportedQeIdentityFormat },
    qe_identity_mismatch = { quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH, QlError::QeIdentityMismatch },
    tcb_out_of_date = { quote3_error_t::SGX_QL_TCB_OUT_OF_DATE, QlError::TcbOutOfDate },
    tcb_out_of_date_and_configuration_needed = { quote3_error_t::SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED, QlError::TcbOutOfDateAndConfigurationNeeded },
    enclave_identity_out_of_date = { quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE, QlError::EnclaveIdentityOutOfDate },
    enclave_report_isvsvn_out_of_date = { quote3_error_t::SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE, QlError::EnclaveReportIsvSvnOutOfDate },
    qe_identity_out_of_date = { quote3_error_t::SGX_QL_QE_IDENTITY_OUT_OF_DATE, QlError::QeIdentityOutOfDate },
    tcb_info_expired = { quote3_error_t::SGX_QL_SGX_TCB_INFO_EXPIRED, QlError::TcbInfoExpired },
    sgx_pck_cert_chain_expired = { quote3_error_t::SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED, QlError::SgxPckCertChainExpired },
    sgx_crl_expired = { quote3_error_t::SGX_QL_SGX_CRL_EXPIRED, QlError::SgxCrlExpired },
    sgx_signing_cert_chain_expired = { quote3_error_t::SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED, QlError::SgxSigningCertChainExpired },
    sgx_enclave_identity_expired = { quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED, QlError::SgxEnclaveIdentityExpired },
    pck_revoked = { quote3_error_t::SGX_QL_PCK_REVOKED, QlError::PckRevoked },
    tcb_revoked = { quote3_error_t::SGX_QL_TCB_REVOKED, QlError::TcbRevoked },
    tcb_configuration_needed = { quote3_error_t::SGX_QL_TCB_CONFIGURATION_NEEDED, QlError::TcbConfigurationNeeded },
    unable_to_get_collateral = { quote3_error_t::SGX_QL_UNABLE_TO_GET_COLLATERAL, QlError::UnableToGetCollateral },
    invalid_privilege = { quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE, QlError::InvalidPrivilege },
    no_qve_identity_data = { quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA, QlError::NoQveIdentityData },
    unsupported_crl_format = { quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT, QlError::UnsupportedCrlFormat },
    qe_identity_chain_error = { quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR, QlError::QeIdentityChainError },
    tcb_info_chain_error = { quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR, QlError::TcbInfoChainError },
    qvl_qve_mismatch = { quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH, QlError::QvlQveMismatch },
    tcb_sw_hardening_needed = { quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED, QlError::TcbSwHardeningNeeded },
    tcb_configuration_and_sw_hardening_needed = { quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED, QlError::TcbConfigurationAndSwHardeningNeeded },
    unsupported_mode = { quote3_error_t::SGX_QL_UNSUPPORTED_MODE, QlError::UnsupportedMode },
    no_device = { quote3_error_t::SGX_QL_NO_DEVICE, QlError::NoDevice },
    service_unavailable = { quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE, QlError::ServiceUnavailable },
    network_failure = { quote3_error_t::SGX_QL_NETWORK_FAILURE, QlError::NetworkFailure },
    service_timeout = { quote3_error_t::SGX_QL_SERVICE_TIMEOUT, QlError::ServiceTimeout },
    busy = { quote3_error_t::SGX_QL_ERROR_BUSY, QlError::Busy },
    unknown_message_response = { quote3_error_t::SGX_QL_UNKNOWN_MESSAGE_RESPONSE, QlError::UnknownMessageResponse },
    persistent_storage = { quote3_error_t::SGX_QL_PERSISTENT_STORAGE_ERROR, QlError::PersistentStorage },
    message_parsing = { quote3_error_t::SGX_QL_ERROR_MESSAGE_PARSING_ERROR, QlError::MessageParsing },
    platform_unknown = { quote3_error_t::SGX_QL_PLATFORM_UNKNOWN, QlError::PlatformUnknown },
    unknown_api_version = { quote3_error_t::SGX_QL_UNKNOWN_API_VERSION, QlError::UnknownApiVersion },
    certs_unavailable = { quote3_error_t::SGX_QL_CERTS_UNAVAILABLE, QlError::CertsUnavailable },
    qve_identity_mismatch = { quote3_error_t::SGX_QL_QVEIDENTITY_MISMATCH, QlError::QveIdentityMismatch },
    qve_out_of_date = { quote3_error_t::SGX_QL_QVE_OUT_OF_DATE, QlError::QveOutOfDate },
    psw_not_available = { quote3_error_t::SGX_QL_PSW_NOT_AVAILABLE, QlError::PswNotAvailable },
    collateral_version_not_supported = { quote3_error_t::SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED, QlError::CollateralVersionNotSupported },
    tdx_module_mismatch = { quote3_error_t::SGX_QL_TDX_MODULE_MISMATCH, QlError::TdxModuleMismatch },
    qe_identity_not_found = { quote3_error_t::SGX_QL_QEIDENTITY_NOT_FOUND, QlError::QeIdentityNotFound },
    tcb_info_not_found = { quote3_error_t::SGX_QL_TCBINFO_NOT_FOUND, QlError::TcbInfoNotFound },
    internal_server_error = { quote3_error_t::SGX_QL_INTERNAL_SERVER_ERROR, QlError::InternalServerError },
    supplemental_data_version_not_supported = { quote3_error_t::SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED, QlError::SupplementalDataVersionNotSupported },
    root_ca_untrusted = { quote3_error_t::SGX_QL_ROOT_CA_UNTRUSTED, QlError::RootCaUntrusted },
    tcb_not_supported = { quote3_error_t::SGX_QL_TCB_NOT_SUPPORTED, QlError::TcbNotSupported },
    max = { quote3_error_t::SGX_QL_ERROR_MAX, QlError::Max }
    )]
    fn error_from_ffi(ffi: quote3_error_t, expected: QlError) {
        assert_eq!(
            expected,
            QlError::try_from(ffi).expect("Could not create error from ffi type")
        )
    }

    #[test]
    fn success_is_not_an_error() {
        assert!(QlError::try_from(quote3_error_t::SGX_QL_SUCCESS).is_err())
    }

    #[test]
    fn unknown_quote3_error_maps_to_unexpected() {
        let unknown = quote3_error_t(quote3_error_t::SGX_QL_ERROR_MAX.0 + 1);
        assert_eq!(
            QlError::try_from(unknown).expect("Could not parse an unknown SGX Status"),
            QlError::Unexpected
        );
    }
}
