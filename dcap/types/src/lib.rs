// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]

use displaydoc::Display;
use mc_sgx_dcap_sys_types::quote3_error_t;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "alloc")]
extern crate alloc;

/// An enumeration of Quote3 errors
#[derive(Copy, Clone, Debug, Display, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[cfg_attr(feature = "alloc", derive(Deserialize, Serialize))]
#[non_exhaustive]
#[repr(u32)]
pub enum Quote3Error {
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
    UnsupportedAttKeyId = quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID.0,

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

    /// The platform library doesn't have any platfrom cert data
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

    /// The format of the PCK Cert is unsupported
    UnsupportedPckCertFormat = quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT.0,

    /**
     * There was an error verifying the PCK Cert signature chain (including
     * PCK Cert revocation)
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

    /// ?
    InvalidPrivilege = quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE.0,

    /// No enough privilege to perform the operation
    NoQveIdentityData = quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA.0,

    /// The platform does not have the QVE identity data available.
    UnsupportedCrlFormat = quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT.0,

    /// ?
    QeIdentityChainError = quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR.0,

    /// ?
    TcbInfoChainError = quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR.0,

    /// ?
    QvlQveMismatch = quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH.0,

    /// QvE returned supplemental data version mismatched between QVL and QvE
    TcbSwHardeningNeeded = quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED.0,

    /// TCB up to date but SW Hardening needed
    TcbConfigurationAndSwHardeningNeeded =
        quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED.0,

    /// TCB up to date but Configuration and SW Hardening needed
    UnsupportedMode = quote3_error_t::SGX_QL_UNSUPPORTED_MODE.0,

    /// ?
    NoDevice = quote3_error_t::SGX_QL_NO_DEVICE.0,

    /// ?
    ServiceUnavailable = quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE.0,

    /// ?
    NetworkFailure = quote3_error_t::SGX_QL_NETWORK_FAILURE.0,

    /// ?
    ServiceTimeout = quote3_error_t::SGX_QL_SERVICE_TIMEOUT.0,

    /// ?
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

// "_quote3_error_t",
// "_sgx_ql_qe3_id_t",
// "_sgx_ql_config_t",
// "_sgx_ql_config_version_t",
// "_sgx_ql_pck_cert_id_t",
// "_sgx_ql_qve_collateral_param_t",
// "_sgx_ql_qve_collateral_t",
// "_sgx_ql_log_level_t",
// "_sgx_prod_type_t",
// "sgx_ql_logging_callback_t",
// "_sgx_pce_error_t",
// "_sgx_ql_request_policy",
// "_sgx_pce_info_t",
// "_sgx_ql_att_key_id_param_t",
// "_sgx_ql_att_id_list_t",
// "_sgx_ql_qe_report_info_t",
// "sgx_ql_attestation_algorithm_id_t",
// "sgx_ql_cert_key_type_t",
// "_sgx_ql_att_key_id_list_header_t",
// "_sgx_ql_ppid_cleartext_cert_info_t",
// "_sgx_ql_ppid_rsa2048_encrypted_cert_info_t",
// "_sgx_ql_ppid_rsa3072_encrypted_cert_info_t",
// "_sgx_ql_auth_data_t",
// "_sgx_ql_certification_data_t",
// "_sgx_ql_ecdsa_sig_data_t",
// "_sgx_quote_header_t",
// "_sgx_quote3_t",
// "_sgx_ql_qv_result_t",
// "_pck_cert_flag_enum_t",
// "_sgx_ql_qv_supplemental_t",
