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
pub enum SgxError {
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

impl TryFrom<quote3_error_t> for SgxError {
    type Error = ();

    fn try_from(value: quote3_error_t) -> Result<Self, Self::Error> {
        match value {
            quote3_error_t::SGX_QL_SUCCESS => Err(()),

            quote3_error_t::SGX_QL_ERROR_UNEXPECTED => Ok(SgxError::Unexpected),
            quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER => Ok(SgxError::InvalidParameter),
            quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY => Ok(SgxError::OutOfMemory),
            quote3_error_t::SGX_QL_ERROR_ECDSA_ID_MISMATCH => Ok(SgxError::EcdsaIdMismatch),
            quote3_error_t::SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR => {
                Ok(SgxError::PathnameBufferOverflow)
            }
            quote3_error_t::SGX_QL_FILE_ACCESS_ERROR => Ok(SgxError::FileAccess),
            quote3_error_t::SGX_QL_ERROR_STORED_KEY => Ok(SgxError::StoredKey),
            quote3_error_t::SGX_QL_ERROR_PUB_KEY_ID_MISMATCH => Ok(SgxError::PubKeyIdMismatch),
            quote3_error_t::SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME => {
                Ok(SgxError::InvalidPceSigScheme)
            }
            quote3_error_t::SGX_QL_ATT_KEY_BLOB_ERROR => Ok(SgxError::AttestationKeyBlob),
            quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID => {
                Ok(SgxError::UnsupportedAttestationKeyId)
            }
            quote3_error_t::SGX_QL_UNSUPPORTED_LOADING_POLICY => {
                Ok(SgxError::UnsupportedLoadingPolicy)
            }
            quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE => Ok(SgxError::InterfaceUnavailable),
            quote3_error_t::SGX_QL_PLATFORM_LIB_UNAVAILABLE => Ok(SgxError::PlatformLibUnavailable),
            quote3_error_t::SGX_QL_ATT_KEY_NOT_INITIALIZED => {
                Ok(SgxError::AttestationKeyNotInitialized)
            }
            quote3_error_t::SGX_QL_ATT_KEY_CERT_DATA_INVALID => {
                Ok(SgxError::InvalidCertDataInAttestationKey)
            }
            quote3_error_t::SGX_QL_NO_PLATFORM_CERT_DATA => Ok(SgxError::NoPlatformCertData),
            quote3_error_t::SGX_QL_OUT_OF_EPC => Ok(SgxError::OutOfEpc),
            quote3_error_t::SGX_QL_ERROR_REPORT => Ok(SgxError::Report),
            quote3_error_t::SGX_QL_ENCLAVE_LOST => Ok(SgxError::EnclaveLost),
            quote3_error_t::SGX_QL_INVALID_REPORT => Ok(SgxError::InvalidReport),
            quote3_error_t::SGX_QL_ENCLAVE_LOAD_ERROR => Ok(SgxError::EnclaveLoad),
            quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_QE_REPORT => {
                Ok(SgxError::UnableToGenerateQeReport)
            }
            quote3_error_t::SGX_QL_KEY_CERTIFCATION_ERROR => Ok(SgxError::KeyCertification),
            quote3_error_t::SGX_QL_NETWORK_ERROR => Ok(SgxError::Network),
            quote3_error_t::SGX_QL_MESSAGE_ERROR => Ok(SgxError::Message),
            quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA => Ok(SgxError::NoQuoteCollateralData),
            quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED => {
                Ok(SgxError::UnsupportedQuoteCertificationData)
            }
            quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED => Ok(SgxError::UnsupportedQuoteFormat),
            quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT => {
                Ok(SgxError::UnableToGenerateReport)
            }
            quote3_error_t::SGX_QL_QE_REPORT_INVALID_SIGNATURE => {
                Ok(SgxError::InvalidQeReportSignature)
            }
            quote3_error_t::SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT => {
                Ok(SgxError::UnsupportedQeReportFormat)
            }
            quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT => {
                Ok(SgxError::UnsupportedPckCertFormat)
            }
            quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR => Ok(SgxError::PckCertChain),
            quote3_error_t::SGX_QL_TCBINFO_UNSUPPORTED_FORMAT => {
                Ok(SgxError::UnsupportedTcbInfoFormat)
            }
            quote3_error_t::SGX_QL_TCBINFO_MISMATCH => Ok(SgxError::TcbInfoMismatch),
            quote3_error_t::SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT => {
                Ok(SgxError::UnsupportedQeIdentityFormat)
            }
            quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH => Ok(SgxError::QeIdentityMismatch),
            quote3_error_t::SGX_QL_TCB_OUT_OF_DATE => Ok(SgxError::TcbOutOfDate),
            quote3_error_t::SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED => {
                Ok(SgxError::TcbOutOfDateAndConfigurationNeeded)
            }
            quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE => {
                Ok(SgxError::EnclaveIdentityOutOfDate)
            }
            quote3_error_t::SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE => {
                Ok(SgxError::EnclaveReportIsvSvnOutOfDate)
            }
            quote3_error_t::SGX_QL_QE_IDENTITY_OUT_OF_DATE => Ok(SgxError::QeIdentityOutOfDate),
            quote3_error_t::SGX_QL_SGX_TCB_INFO_EXPIRED => Ok(SgxError::TcbInfoExpired),
            quote3_error_t::SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED => {
                Ok(SgxError::SgxPckCertChainExpired)
            }
            quote3_error_t::SGX_QL_SGX_CRL_EXPIRED => Ok(SgxError::SgxCrlExpired),
            quote3_error_t::SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED => {
                Ok(SgxError::SgxSigningCertChainExpired)
            }
            quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED => {
                Ok(SgxError::SgxEnclaveIdentityExpired)
            }
            quote3_error_t::SGX_QL_PCK_REVOKED => Ok(SgxError::PckRevoked),
            quote3_error_t::SGX_QL_TCB_REVOKED => Ok(SgxError::TcbRevoked),
            quote3_error_t::SGX_QL_TCB_CONFIGURATION_NEEDED => Ok(SgxError::TcbConfigurationNeeded),
            quote3_error_t::SGX_QL_UNABLE_TO_GET_COLLATERAL => Ok(SgxError::UnableToGetCollateral),
            quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE => Ok(SgxError::InvalidPrivilege),
            quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA => Ok(SgxError::NoQveIdentityData),
            quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT => Ok(SgxError::UnsupportedCrlFormat),
            quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR => Ok(SgxError::QeIdentityChainError),
            quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR => Ok(SgxError::TcbInfoChainError),
            quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH => Ok(SgxError::QvlQveMismatch),
            quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED => Ok(SgxError::TcbSwHardeningNeeded),
            quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED => {
                Ok(SgxError::TcbConfigurationAndSwHardeningNeeded)
            }
            quote3_error_t::SGX_QL_UNSUPPORTED_MODE => Ok(SgxError::UnsupportedMode),
            quote3_error_t::SGX_QL_NO_DEVICE => Ok(SgxError::NoDevice),
            quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE => Ok(SgxError::ServiceUnavailable),
            quote3_error_t::SGX_QL_NETWORK_FAILURE => Ok(SgxError::NetworkFailure),
            quote3_error_t::SGX_QL_SERVICE_TIMEOUT => Ok(SgxError::ServiceTimeout),
            quote3_error_t::SGX_QL_ERROR_BUSY => Ok(SgxError::Busy),
            quote3_error_t::SGX_QL_UNKNOWN_MESSAGE_RESPONSE => Ok(SgxError::UnknownMessageResponse),
            quote3_error_t::SGX_QL_PERSISTENT_STORAGE_ERROR => Ok(SgxError::PersistentStorage),
            quote3_error_t::SGX_QL_ERROR_MESSAGE_PARSING_ERROR => Ok(SgxError::MessageParsing),
            quote3_error_t::SGX_QL_PLATFORM_UNKNOWN => Ok(SgxError::PlatformUnknown),
            quote3_error_t::SGX_QL_UNKNOWN_API_VERSION => Ok(SgxError::UnknownApiVersion),
            quote3_error_t::SGX_QL_CERTS_UNAVAILABLE => Ok(SgxError::CertsUnavailable),
            quote3_error_t::SGX_QL_QVEIDENTITY_MISMATCH => Ok(SgxError::QveIdentityMismatch),
            quote3_error_t::SGX_QL_QVE_OUT_OF_DATE => Ok(SgxError::QveOutOfDate),
            quote3_error_t::SGX_QL_PSW_NOT_AVAILABLE => Ok(SgxError::PswNotAvailable),
            quote3_error_t::SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED => {
                Ok(SgxError::CollateralVersionNotSupported)
            }
            quote3_error_t::SGX_QL_TDX_MODULE_MISMATCH => Ok(SgxError::TdxModuleMismatch),
            quote3_error_t::SGX_QL_ERROR_MAX => Ok(SgxError::Max),
            // Map all unknowns to the unexpected error
            _ => Ok(SgxError::Unexpected),
        }
    }
}

impl From<SgxError> for quote3_error_t {
    fn from(src: SgxError) -> quote3_error_t {
        quote3_error_t(src as u32)
    }
}

impl ResultFrom<quote3_error_t> for SgxError {}
impl ResultInto<SgxError> for quote3_error_t {}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use yare::parameterized;

    #[parameterized(
    unexpected = { quote3_error_t::SGX_QL_ERROR_UNEXPECTED, SgxError::Unexpected },
    invalid_parameter = { quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER, SgxError::InvalidParameter },
    out_of_memory = { quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY, SgxError::OutOfMemory },
    ecdsa_id_mismatch = { quote3_error_t::SGX_QL_ERROR_ECDSA_ID_MISMATCH, SgxError::EcdsaIdMismatch },
    pathname_buffer_overflow = { quote3_error_t::SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR, SgxError::PathnameBufferOverflow },
    file_access = { quote3_error_t::SGX_QL_FILE_ACCESS_ERROR, SgxError::FileAccess },
    stored_key = { quote3_error_t::SGX_QL_ERROR_STORED_KEY, SgxError::StoredKey },
    pub_key_id_mismatch = { quote3_error_t::SGX_QL_ERROR_PUB_KEY_ID_MISMATCH, SgxError::PubKeyIdMismatch },
    invalid_pce_sig_scheme = { quote3_error_t::SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME, SgxError::InvalidPceSigScheme },
    attestation_key_blob = { quote3_error_t::SGX_QL_ATT_KEY_BLOB_ERROR, SgxError::AttestationKeyBlob },
    unsupported_att_key_id = { quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID, SgxError::UnsupportedAttestationKeyId },
    unsupported_loading_policy = { quote3_error_t::SGX_QL_UNSUPPORTED_LOADING_POLICY, SgxError::UnsupportedLoadingPolicy },
    interface_unavailable = { quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE, SgxError::InterfaceUnavailable },
    platform_lib_unavailable = { quote3_error_t::SGX_QL_PLATFORM_LIB_UNAVAILABLE, SgxError::PlatformLibUnavailable },
    attestation_key_not_initialized = { quote3_error_t::SGX_QL_ATT_KEY_NOT_INITIALIZED, SgxError::AttestationKeyNotInitialized },
    invalid_cert_data_in_attestation_key = { quote3_error_t::SGX_QL_ATT_KEY_CERT_DATA_INVALID, SgxError::InvalidCertDataInAttestationKey },
    no_platform_cert_data = { quote3_error_t::SGX_QL_NO_PLATFORM_CERT_DATA, SgxError::NoPlatformCertData },
    out_of_epc = { quote3_error_t::SGX_QL_OUT_OF_EPC, SgxError::OutOfEpc },
    report = { quote3_error_t::SGX_QL_ERROR_REPORT, SgxError::Report },
    enclave_lost = { quote3_error_t::SGX_QL_ENCLAVE_LOST, SgxError::EnclaveLost },
    invalid_report = { quote3_error_t::SGX_QL_INVALID_REPORT, SgxError::InvalidReport },
    enclave_load = { quote3_error_t::SGX_QL_ENCLAVE_LOAD_ERROR, SgxError::EnclaveLoad },
    unable_to_generate_qe_report = { quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_QE_REPORT, SgxError::UnableToGenerateQeReport },
    key_certification = { quote3_error_t::SGX_QL_KEY_CERTIFCATION_ERROR, SgxError::KeyCertification },
    network = { quote3_error_t::SGX_QL_NETWORK_ERROR, SgxError::Network },
    message = { quote3_error_t::SGX_QL_MESSAGE_ERROR, SgxError::Message },
    no_quote_collateral_data = { quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA, SgxError::NoQuoteCollateralData },
    unsupported_quote_certification_data = { quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED, SgxError::UnsupportedQuoteCertificationData },
    unsupported_quote_format = { quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED, SgxError::UnsupportedQuoteFormat },
    unable_to_generate_report = { quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT, SgxError::UnableToGenerateReport },
    invalid_qe_report_signature = { quote3_error_t::SGX_QL_QE_REPORT_INVALID_SIGNATURE, SgxError::InvalidQeReportSignature },
    unsupported_qe_report_format = { quote3_error_t::SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT, SgxError::UnsupportedQeReportFormat },
    unsupported_pck_cert_format = { quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT, SgxError::UnsupportedPckCertFormat },
    pck_cert_chain = { quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR, SgxError::PckCertChain },
    unsupported_tcb_info_format = { quote3_error_t::SGX_QL_TCBINFO_UNSUPPORTED_FORMAT, SgxError::UnsupportedTcbInfoFormat },
    tcb_info_mismatch = { quote3_error_t::SGX_QL_TCBINFO_MISMATCH, SgxError::TcbInfoMismatch },
    unsupported_qe_identity_format = { quote3_error_t::SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT, SgxError::UnsupportedQeIdentityFormat },
    qe_identity_mismatch = { quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH, SgxError::QeIdentityMismatch },
    tcb_out_of_date = { quote3_error_t::SGX_QL_TCB_OUT_OF_DATE, SgxError::TcbOutOfDate },
    tcb_out_of_date_and_configuration_needed = { quote3_error_t::SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED, SgxError::TcbOutOfDateAndConfigurationNeeded },
    enclave_identity_out_of_date = { quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE, SgxError::EnclaveIdentityOutOfDate },
    enclave_report_isvsvn_out_of_date = { quote3_error_t::SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE, SgxError::EnclaveReportIsvSvnOutOfDate },
    qe_identity_out_of_date = { quote3_error_t::SGX_QL_QE_IDENTITY_OUT_OF_DATE, SgxError::QeIdentityOutOfDate },
    tcb_info_expired = { quote3_error_t::SGX_QL_SGX_TCB_INFO_EXPIRED, SgxError::TcbInfoExpired },
    sgx_pck_cert_chain_expired = { quote3_error_t::SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED, SgxError::SgxPckCertChainExpired },
    sgx_crl_expired = { quote3_error_t::SGX_QL_SGX_CRL_EXPIRED, SgxError::SgxCrlExpired },
    sgx_signing_cert_chain_expired = { quote3_error_t::SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED, SgxError::SgxSigningCertChainExpired },
    sgx_enclave_identity_expired = { quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED, SgxError::SgxEnclaveIdentityExpired },
    pck_revoked = { quote3_error_t::SGX_QL_PCK_REVOKED, SgxError::PckRevoked },
    tcb_revoked = { quote3_error_t::SGX_QL_TCB_REVOKED, SgxError::TcbRevoked },
    tcb_configuration_needed = { quote3_error_t::SGX_QL_TCB_CONFIGURATION_NEEDED, SgxError::TcbConfigurationNeeded },
    unable_to_get_collateral = { quote3_error_t::SGX_QL_UNABLE_TO_GET_COLLATERAL, SgxError::UnableToGetCollateral },
    invalid_privilege = { quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE, SgxError::InvalidPrivilege },
    no_qve_identity_data = { quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA, SgxError::NoQveIdentityData },
    unsupported_crl_format = { quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT, SgxError::UnsupportedCrlFormat },
    qe_identity_chain_error = { quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR, SgxError::QeIdentityChainError },
    tcb_info_chain_error = { quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR, SgxError::TcbInfoChainError },
    qvl_qve_mismatch = { quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH, SgxError::QvlQveMismatch },
    tcb_sw_hardening_needed = { quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED, SgxError::TcbSwHardeningNeeded },
    tcb_configuration_and_sw_hardening_needed = { quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED, SgxError::TcbConfigurationAndSwHardeningNeeded },
    unsupported_mode = { quote3_error_t::SGX_QL_UNSUPPORTED_MODE, SgxError::UnsupportedMode },
    no_device = { quote3_error_t::SGX_QL_NO_DEVICE, SgxError::NoDevice },
    service_unavailable = { quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE, SgxError::ServiceUnavailable },
    network_failure = { quote3_error_t::SGX_QL_NETWORK_FAILURE, SgxError::NetworkFailure },
    service_timeout = { quote3_error_t::SGX_QL_SERVICE_TIMEOUT, SgxError::ServiceTimeout },
    busy = { quote3_error_t::SGX_QL_ERROR_BUSY, SgxError::Busy },
    unknown_message_response = { quote3_error_t::SGX_QL_UNKNOWN_MESSAGE_RESPONSE, SgxError::UnknownMessageResponse },
    persistent_storage = { quote3_error_t::SGX_QL_PERSISTENT_STORAGE_ERROR, SgxError::PersistentStorage },
    message_parsing = { quote3_error_t::SGX_QL_ERROR_MESSAGE_PARSING_ERROR, SgxError::MessageParsing },
    platform_unknown = { quote3_error_t::SGX_QL_PLATFORM_UNKNOWN, SgxError::PlatformUnknown },
    unknown_api_version = { quote3_error_t::SGX_QL_UNKNOWN_API_VERSION, SgxError::UnknownApiVersion },
    certs_unavailable = { quote3_error_t::SGX_QL_CERTS_UNAVAILABLE, SgxError::CertsUnavailable },
    qve_identity_mismatch = { quote3_error_t::SGX_QL_QVEIDENTITY_MISMATCH, SgxError::QveIdentityMismatch },
    qve_out_of_date = { quote3_error_t::SGX_QL_QVE_OUT_OF_DATE, SgxError::QveOutOfDate },
    psw_not_available = { quote3_error_t::SGX_QL_PSW_NOT_AVAILABLE, SgxError::PswNotAvailable },
    collateral_version_not_supported = { quote3_error_t::SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED, SgxError::CollateralVersionNotSupported },
    tdx_module_mismatch = { quote3_error_t::SGX_QL_TDX_MODULE_MISMATCH, SgxError::TdxModuleMismatch },
    max = { quote3_error_t::SGX_QL_ERROR_MAX, SgxError::Max }
    )]
    fn error_from_ffi(ffi: quote3_error_t, expected: SgxError) {
        assert_eq!(
            expected,
            SgxError::try_from(ffi).expect("Could not create error from ffi type")
        )
    }

    #[test]
    fn success_is_not_an_error() {
        assert!(SgxError::try_from(quote3_error_t::SGX_QL_SUCCESS).is_err())
    }

    #[test]
    fn unknown_quote3_error_maps_to_unexpected() {
        let unknown = quote3_error_t(quote3_error_t::SGX_QL_ERROR_MAX.0 + 1);
        assert_eq!(
            SgxError::try_from(unknown).expect("Could not parse an unknown SGX Status"),
            SgxError::Unexpected
        );
    }
}
