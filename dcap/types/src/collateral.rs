// Copyright (c) 2023 The MobileCoin Foundation

//! Collateral for a quote.
//!
//! The collateral is additional data that is used to verify the contents of a
//! [`Quote3`].

extern crate alloc;

use alloc::string::{FromUtf8Error, String};
use alloc::vec::Vec;
use mc_sgx_dcap_sys_types::sgx_ql_qve_collateral_t;
use x509_cert::crl::CertificateList;
use x509_cert::der::Decode;
use x509_cert::Certificate;

// Per the comment in `sgx_ql_lib_common.h`
//
//      0x00000000: SGX or 0x00000081: TDX
const SGX_TEE: u32 = 0;

// From the comment in `/etc/sgx_default_qcnl.conf`:
//
//      If you use a PCCS service to get the quote verification collateral, you can specify which PCCS API version is to be used.
//      The legacy 3.0 API will return CRLs in HEX encoded DER format and the sgx_ql_qve_collateral_t.version will be set to 3.0, while
//      the new 3.1 API will return raw DER format and the sgx_ql_qve_collateral_t.version will be set to 3.1. The pccs_api_version
//      setting is ignored if collateral_service is set to the Intel PCS. In this case, the pccs_api_version is forced to be 3.1
//      internally.  Currently, only values of 3.0 and 3.1 are valid.  Note, if you set this to 3.1, the PCCS use to retrieve
//      verification collateral must support the new 3.1 APIs.
//
// This version can be ensured by setting the `pccs_api_version` key of `/etc/sgx_default_qcnl.conf`
// to `3.1`.
//
//      ,"pccs_api_version": "3.1"
//
const VERSION_MAJOR: u16 = 3;
const VERSION_MINOR: u16 = 1;

/// Error creating a [`Collateral`]
#[derive(Debug, displaydoc::Display, Clone, Eq, PartialEq)]
pub enum Error {
    /// Error converting from DER {0}
    Der(x509_cert::der::Error),
    /// Unsupported version, expected 3.1, but got {0}.{1}
    Version(u16, u16),
    /// Unsupported collateral service, expected SGX (0), but got {0}
    CollateralService(u32),
    /// Error converting bytes to String {0}
    Utf8(FromUtf8Error),
    /// One of the collateral fields is missing
    MissingCollateral,
}

impl From<x509_cert::der::Error> for Error {
    fn from(err: x509_cert::der::Error) -> Self {
        Self::Der(err)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Self::Utf8(err)
    }
}

/// Collateral for a quote.
///
/// This data can be retrieved from the individual endpoints:
/// - <https://api.portal.trustedservices.intel.com/documentation#pcs-revocation-v4>
/// - <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4>
/// - <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
/// - <https://certificates.trustedservices.intel.com/IntelSGXRootCA.der>
///
/// or the data can be retrieved from `sgx_ql_get_quote_verification_collateral()`
///
/// The certificate chains and CRLs are documented in
/// <https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf>
#[derive(Debug, Clone)]
pub struct Collateral {
    root_ca_crl: CertificateList,
    pck_crl_issuer_chain: Vec<Certificate>,
    pck_crl: CertificateList,
    tcb_issuer_chain: Vec<Certificate>,
    tcb_info: String,
    qe_identity_issuer_chain: Vec<Certificate>,
    qe_identity: String,
}

impl Collateral {
    /// Get the root certificate authority (CA) certificate revocation list
    /// (CRL).
    ///
    /// This will be the "Intel® SGX Root CA CRL" described in
    /// <https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf>.
    ///
    /// It can manually be retrieved from
    /// <https://certificates.trustedservices.intel.com/IntelSGXRootCA.der>
    pub fn root_ca_crl(&self) -> &CertificateList {
        &self.root_ca_crl
    }

    /// Get the Provisioning Certification Key (PCK) certificate revocation
    /// list (CRL) issuer chain.
    ///
    /// This is the x509 certificate chain that can verify the [`pck_crl()`].
    pub fn pck_crl_issuer_chain(&self) -> &[Certificate] {
        &self.pck_crl_issuer_chain
    }

    /// Get the Get the Provisioning Certification Key (PCK) certificate revocation
    /// list (CRL).
    ///
    /// This will be the "Intel® SGX PCK Processor CA CRL" described in
    /// <https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf>.
    pub fn pck_crl(&self) -> &CertificateList {
        &self.pck_crl
    }

    /// Get the Trusted Computing Base (TCB) issuer chain.
    ///
    /// This is the x509 certificate chain that can verify the [`tcb_info()`].
    pub fn tcb_issuer_chain(&self) -> &[Certificate] {
        &self.tcb_issuer_chain
    }

    /// Get the Trusted Computing Base (TCB) info.
    ///
    /// JSON formatted TCB info described at
    /// <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4>
    pub fn tcb_info(&self) -> &str {
        &self.tcb_info
    }

    /// Get the Quoting Enclave (QE) identity issuer chain.
    ///
    /// This is the x509 certificate chain that can verify the [`qe_identity()`].
    pub fn qe_identity_issuer_chain(&self) -> &[Certificate] {
        &self.qe_identity_issuer_chain
    }

    /// Get the Quoting Enclave (QE) identity.
    ///
    /// JSON formatted QE identity info described at
    /// <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
    pub fn qe_identity(&self) -> &str {
        &self.qe_identity
    }
}

impl TryFrom<&sgx_ql_qve_collateral_t> for Collateral {
    type Error = Error;

    fn try_from(collateral: &sgx_ql_qve_collateral_t) -> Result<Self, Self::Error> {
        ensure_version(collateral)?;
        let root_ca_crl = crl_from_bytes(collateral.root_ca_crl, collateral.root_ca_crl_size)?;
        let pck_crl_issuer_chain = cert_chain_from_bytes(
            collateral.pck_crl_issuer_chain,
            collateral.pck_crl_issuer_chain_size,
        )?;
        let pck_crl = crl_from_bytes(collateral.pck_crl, collateral.pck_crl_size)?;
        let tcb_issuer_chain = cert_chain_from_bytes(
            collateral.tcb_info_issuer_chain,
            collateral.tcb_info_issuer_chain_size,
        )?;
        let tcb_info = string_from_bytes(collateral.tcb_info, collateral.tcb_info_size)?;
        let qe_identity_issuer_chain = cert_chain_from_bytes(
            collateral.qe_identity_issuer_chain,
            collateral.qe_identity_issuer_chain_size,
        )?;
        let qe_identity = string_from_bytes(collateral.qe_identity, collateral.qe_identity_size)?;

        Ok(Self {
            root_ca_crl,
            pck_crl_issuer_chain,
            pck_crl,
            tcb_issuer_chain,
            tcb_info,
            qe_identity_issuer_chain,
            qe_identity,
        })
    }
}

fn string_from_bytes(bytes: *mut core::ffi::c_char, size: u32) -> Result<String, Error> {
    // For the `size == 0`, an empty string is generally valid, but we error
    // for consistent behavior with the other `***_from_bytes()` functions.
    if bytes.is_null() || size == 0 {
        return Err(Error::MissingCollateral);
    }

    // SAFETY: The `bytes` are provided from a C API, we have to trust they are
    // valid. This function returns a value which copies from the `bytes` and
    // thus no longer references the `bytes`.
    #[allow(unsafe_code)]
    let slice = unsafe { core::slice::from_raw_parts(bytes as *const u8, size as usize) };
    Ok(String::from_utf8(slice.to_vec())?)
}

fn crl_from_bytes(bytes: *const core::ffi::c_char, size: u32) -> Result<CertificateList, Error> {
    if bytes.is_null() {
        return Err(Error::MissingCollateral);
    }

    // SAFETY: The `bytes` are provided from a C API, we have to trust they are
    // valid. This function returns a value which copies from the `bytes` and
    // thus no longer references the `bytes`.
    #[allow(unsafe_code)]
    let slice = unsafe { core::slice::from_raw_parts(bytes as *const u8, size as usize) };

    // The DER encoding has an extra NULL byte at the end.
    // Since DER is a binary format, there is nothing stopping the last valid
    // byte from being 0, because of that we only trim the extra byte and not
    // *all* trailing null bytes via the `trim_null_end()` function
    let [crl @ .., _] = slice else {
        return Err(Error::MissingCollateral);
    };

    Ok(CertificateList::from_der(crl)?)
}

fn cert_chain_from_bytes(
    bytes: *const core::ffi::c_char,
    size: u32,
) -> Result<Vec<Certificate>, Error> {
    if bytes.is_null() {
        return Err(Error::MissingCollateral);
    }

    // SAFETY: The `bytes` are provided from a C API, we have to trust they are
    // valid. This function returns a value which copies from the `bytes` and
    // thus no longer references the `bytes`.
    #[allow(unsafe_code)]
    let slice = unsafe { core::slice::from_raw_parts(bytes as *const u8, size as usize) };

    // The PEM chain ends with a null byte, guessing this is so that the C API
    // can key off the NULL byte instead of the length to terminate parsing. It
    // is not valid PEM to have a NULL byte at the end.
    let pem_chain = trim_null_and_whitespace_end(slice);

    // Must check after trimming the NULL byte(s) because `load_pem_chain()`
    // will try to subtract from 0 and panic, in debug builds, which means it's
    // undefined in release
    if pem_chain.is_empty() {
        return Err(Error::MissingCollateral);
    }

    Ok(Certificate::load_pem_chain(pem_chain)?)
}

fn ensure_version(collateral: &sgx_ql_qve_collateral_t) -> Result<(), Error> {
    // SAFETY: The version fields are a union. Unions are inherently unsafe
    // Per the declaration in `sgx_ql_lib_common.h`:
    //
    //    union {
    //        uint32_t version;           ///< 'version' is the backward compatible legacy representation
    //        struct {                    ///< For PCS V1 and V2 APIs, the major_version = 1 and minor_version = 0 and
    //            uint16_t major_version; ///< the CRLs will be formatted in PEM. For PCS V3 APIs, the major_version = 3 and the
    //            uint16_t minor_version; ///< minor_version can be either 0 or 1. minor_version of 0 indicates the CRL’s are formatted
    //                                    ///< in Base16 encoded DER.  A minor version of 1 indicates the CRL’s are formatted in raw binary DER.
    //        };
    //    };
    //
    // The consolidated `version` is legacy and not used in DCAP.
    // If the `version` were used it would need to be a value of 65539, to be
    // misinterpreted as 3.1
    #[allow(unsafe_code)]
    let version = unsafe { collateral.__bindgen_anon_1.__bindgen_anon_1.as_ref() };

    match (version.major_version, version.minor_version) {
        (VERSION_MAJOR, VERSION_MINOR) => {}
        (major, minor) => return Err(Error::Version(major, minor)),
    };

    match collateral.tee_type {
        SGX_TEE => Ok(()),
        tee_type => Err(Error::CollateralService(tee_type)),
    }
}

// Trim the null and the whitespace characters from the end of the slice.
//
// Implementation more or less copied from the nightly
// [`trim_ascii_end`](https://doc.rust-lang.org/nightly/std/primitive.slice.html#method.trim_ascii_end)
// implementation.
const fn trim_null_and_whitespace_end(slice: &[u8]) -> &[u8] {
    let mut bytes = slice;
    // Note: A pattern matching based approach (instead of indexing) allows
    // making the function const.
    while let [rest @ .., last] = bytes {
        if last.is_ascii_whitespace() || *last == 0 {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{CertificationData, Quote3};
    use alloc::string::String;
    use assert_matches::assert_matches;
    use x509_cert::der::DecodePem;
    use yare::parameterized;

    // Get the cert chain from a quote
    //
    // # Returns
    // The PEM chain as a string the same as the C API would return it, and a vector of the
    // individual certificates
    fn pem_cert_chain() -> (String, Vec<Certificate>) {
        let hw_quote = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(hw_quote.as_ref()).expect("Failed to parse quote");
        let signature_data = quote.signature_data();
        let cert_chain = match signature_data.certification_data() {
            CertificationData::PckCertificateChain(cert_chain) => cert_chain,
            _ => panic!("expected a PckCertChain"),
        };
        let pems = cert_chain
            .into_iter()
            .map(|bytes| {
                String::from(core::str::from_utf8(bytes).expect("Expect valid PEM string"))
            })
            .collect::<Vec<_>>();
        let mut pem_string = pems.join("\n");
        // Add trailing null byte to mimic C string behavior
        pem_string.push('\0');

        let certs = pems
            .iter()
            .map(|pem| Certificate::from_pem(pem.as_bytes()).expect("Expect valid PEM string"))
            .collect::<Vec<_>>();
        (pem_string, certs)
    }

    fn empty_collateral_with_version(major: u16, minor: u16) -> sgx_ql_qve_collateral_t {
        let mut collateral = sgx_ql_qve_collateral_t::default();
        // SAFETY: The version fields are a union, which is inherently unsafe.
        // This is a test only function that sets the major and minor flavor of
        // the union fields.
        #[allow(unsafe_code)]
        unsafe {
            collateral
                .__bindgen_anon_1
                .__bindgen_anon_1
                .as_mut()
                .major_version = major;
            collateral
                .__bindgen_anon_1
                .__bindgen_anon_1
                .as_mut()
                .minor_version = minor;
        }
        collateral
    }

    #[test]
    fn ensure_version_for_3_1_sgx() {
        let mut collateral = empty_collateral_with_version(3, 1);
        collateral.tee_type = SGX_TEE;

        assert!(ensure_version(&collateral).is_ok());
    }

    #[test]
    fn ensure_version_fails_for_non_sgx() {
        let mut collateral = empty_collateral_with_version(3, 1);
        collateral.tee_type = SGX_TEE + 1;

        assert_matches!(ensure_version(&collateral), Err(Error::CollateralService(tee)) if tee == SGX_TEE + 1);
    }

    #[parameterized(
        three_zero = {3, 0},
        three_two = {3, 2},
        two_one = {2, 1},
        four_one = {4, 1},
    )]
    fn ensure_version_fails_for_wrong_version(major: u16, minor: u16) {
        let mut collateral = empty_collateral_with_version(major, minor);
        collateral.tee_type = SGX_TEE;

        assert_matches!(ensure_version(&collateral), Err(Error::Version(seen_major, seen_minor)) if seen_major == major && seen_minor == minor);
    }

    #[test]
    fn collateral_from_wrong_version_fails() {
        let collateral = empty_collateral_with_version(3, 0);

        assert_matches!(Collateral::try_from(&collateral), Err(Error::Version(3, seen_minor)) if seen_minor == 0);
    }

    #[test]
    fn valid_cert_chain_from_bytes() {
        let (mut pem_chain, certificates) = pem_cert_chain();
        let cert_chain = cert_chain_from_bytes(
            pem_chain.as_mut_ptr() as *mut core::ffi::c_char,
            pem_chain.len() as u32,
        )
        .expect("Expect valid cert chain");
        assert_eq!(cert_chain, certificates);
    }

    #[test]
    fn null_cert_chain_fails() {
        assert_eq!(
            cert_chain_from_bytes(core::ptr::null_mut(), 10),
            Err(Error::MissingCollateral)
        );
    }

    #[test]
    fn empty_cert_chain_fails() {
        let (mut pem_chain, _) = pem_cert_chain();
        // Passing an empty slice into the PEM decoder will cause a panic so we
        // catch the 0 length and return an error instead.
        assert_eq!(
            cert_chain_from_bytes(pem_chain.as_mut_ptr() as *mut core::ffi::c_char, 0),
            Err(Error::MissingCollateral)
        );
    }

    #[test]
    fn whitespace_only_cert_chain_fails() {
        let mut pem_chain = String::from(" \n\t\r");
        // Passing a whitespace only slice into the PEM decoder will cause a
        // panic so we normalize before hand, catch the 0 length normalized
        // version and return an error.
        assert_eq!(
            cert_chain_from_bytes(
                pem_chain.as_mut_ptr() as *mut core::ffi::c_char,
                pem_chain.len() as u32
            ),
            Err(Error::MissingCollateral)
        );
    }

    #[test]
    fn valid_crl_from_bytes() {
        let mut der_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        let expected_crl =
            CertificateList::from_der(der_crl.as_slice()).expect("Failed to parse CRL");

        // To mimic the C API we need an extra null byte at the end of the DER
        // The implementation needs to remove this null byte before decoding as it
        // results in an error from the DER decoder if too many bytes are provided.
        der_crl.push(0);

        let crl = crl_from_bytes(
            der_crl.as_mut_ptr() as *mut core::ffi::c_char,
            der_crl.len() as u32,
        )
        .expect("Expect valid CRL");
        assert_eq!(crl, expected_crl);
    }

    #[test]
    fn null_crl_fails() {
        assert_eq!(
            crl_from_bytes(core::ptr::null_mut(), 10),
            Err(Error::MissingCollateral)
        );
    }

    #[test]
    fn empty_crl_fails() {
        let mut der_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        der_crl.push(0);

        assert_eq!(
            crl_from_bytes(der_crl.as_mut_ptr() as *mut core::ffi::c_char, 0),
            Err(Error::MissingCollateral)
        );
    }

    #[test]
    fn almost_empty_crl_fails() {
        let mut der_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        der_crl.push(0);

        // We pass in a size of one to account for `crl_from_bytes()` trimming
        // the trailing byte. This should result in a slice of length 0 getting
        // passed to the DER decoder. This was desired to ensure the DER
        // decoding didn't panic/overflow when provided an empty slice, like
        // the PEM decoder used in `cert_chain_from_bytes()`
        assert_matches!(
            crl_from_bytes(der_crl.as_mut_ptr() as *mut core::ffi::c_char, 1),
            Err(Error::Der(_))
        );
    }

    #[test]
    fn valid_string_from_bytes() {
        let mut byte_string = String::from("The Legend of Chavo Guerrero");
        let string = string_from_bytes(
            byte_string.as_mut_ptr() as *mut core::ffi::c_char,
            byte_string.len() as u32,
        )
        .expect("Expect valid string");
        assert_eq!(string, byte_string);
    }

    #[test]
    fn null_string_fails() {
        assert_eq!(
            string_from_bytes(core::ptr::null_mut(), 10),
            Err(Error::MissingCollateral)
        );
    }

    #[test]
    fn invalid_utf8_string_fails() {
        let mut invalid_utf8 = [b'a', b'b', 0x80, b'c', b'd'].to_vec();
        assert_matches!(
            string_from_bytes(
                invalid_utf8.as_mut_ptr() as *mut core::ffi::c_char,
                invalid_utf8.len() as u32
            ),
            Err(Error::Utf8(_))
        );
    }

    #[test]
    fn empty_string_fails() {
        let mut empty_string = String::new();
        assert_eq!(
            string_from_bytes(
                empty_string.as_mut_ptr() as *mut core::ffi::c_char,
                empty_string.len() as u32
            ),
            Err(Error::MissingCollateral)
        );
    }

    #[test]
    fn valid_collateral() {
        let mut root_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        root_crl.push(0);
        let (mut pem_chain, certificates) = pem_cert_chain();
        let mut pck_crl = include_bytes!("../data/tests/processor_crl.der").to_vec();
        pck_crl.push(0);
        let mut tcb_info = String::from("Hello");
        let mut qe_identity = String::from("World");
        let mut sgx_collateral = empty_collateral_with_version(3, 1);
        sgx_collateral.root_ca_crl = root_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = root_crl.len() as u32;
        sgx_collateral.pck_crl_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.pck_crl = pck_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = pck_crl.len() as u32;
        sgx_collateral.tcb_info_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.len() as u32;
        sgx_collateral.qe_identity_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.len() as u32;

        let collateral =
            Collateral::try_from(&sgx_collateral).expect("Failed to convert collateral");

        root_crl.pop();
        pck_crl.pop();
        let root_ca_crl =
            CertificateList::from_der(root_crl.as_slice()).expect("Failed to parse root CRL");
        let pck_crl =
            CertificateList::from_der(pck_crl.as_slice()).expect("Failed to parse PCK CRL");
        assert_eq!(collateral.pck_crl_issuer_chain, certificates);
        assert_eq!(collateral.root_ca_crl, root_ca_crl);
        assert_eq!(collateral.pck_crl, pck_crl);
        assert_eq!(collateral.tcb_issuer_chain, certificates);
        assert_eq!(collateral.tcb_info, "Hello");
        assert_eq!(collateral.qe_identity_issuer_chain, certificates);
        assert_eq!(collateral.qe_identity, "World");
    }

    #[test]
    fn failure_to_decode_root_crl() {
        let mut root_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        root_crl.push(0);

        // A leading zero byte will be invalid DER
        root_crl[0] = 0;

        let (mut pem_chain, _) = pem_cert_chain();
        let mut pck_crl = include_bytes!("../data/tests/processor_crl.der").to_vec();
        pck_crl.push(0);
        let mut pck_crl = include_bytes!("../data/tests/processor_crl.der").to_vec();
        let mut tcb_info = String::from("Hello");
        let mut qe_identity = String::from("World");
        let mut sgx_collateral = empty_collateral_with_version(3, 1);
        sgx_collateral.root_ca_crl = root_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = root_crl.len() as u32;
        sgx_collateral.pck_crl_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.pck_crl = pck_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = pck_crl.len() as u32;
        sgx_collateral.tcb_info_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.len() as u32;
        sgx_collateral.qe_identity_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.len() as u32;

        assert_matches!(Collateral::try_from(&sgx_collateral), Err(Error::Der(_)));
    }

    #[test]
    fn failure_to_decode_pem_chain() {
        let mut root_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        root_crl.push(0);
        let (mut pem_chain, _) = pem_cert_chain();
        let mut pck_chain = pem_chain.clone();

        // PEM's should start with "-----BEGIN CERTIFICATE-----"
        pck_chain.insert(0, 'a');

        let mut pck_crl = include_bytes!("../data/tests/processor_crl.der").to_vec();
        pck_crl.push(0);
        let mut tcb_info = String::from("Hello");
        let mut qe_identity = String::from("World");
        let mut sgx_collateral = empty_collateral_with_version(3, 1);
        sgx_collateral.root_ca_crl = root_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = root_crl.len() as u32;
        sgx_collateral.pck_crl_issuer_chain = pck_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pck_chain.len() as u32;
        sgx_collateral.pck_crl = pck_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = pck_crl.len() as u32;
        sgx_collateral.tcb_info_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.len() as u32;
        sgx_collateral.qe_identity_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.len() as u32;

        assert_matches!(Collateral::try_from(&sgx_collateral), Err(Error::Der(_)));
    }

    #[test]
    fn failure_to_decode_pck_crl() {
        let mut root_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        root_crl.push(0);
        let (mut pem_chain, _) = pem_cert_chain();
        let mut pck_crl = include_bytes!("../data/tests/processor_crl.der").to_vec();
        pck_crl.push(0);

        // A leading zero byte will be invalid DER
        pck_crl[0] = 0;

        let mut tcb_info = String::from("Hello");
        let mut qe_identity = String::from("World");
        let mut sgx_collateral = empty_collateral_with_version(3, 1);
        sgx_collateral.root_ca_crl = root_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = root_crl.len() as u32;
        sgx_collateral.pck_crl_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.pck_crl = pck_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = pck_crl.len() as u32;
        sgx_collateral.tcb_info_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.len() as u32;
        sgx_collateral.qe_identity_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.len() as u32;

        assert_matches!(Collateral::try_from(&sgx_collateral), Err(Error::Der(_)));
    }

    #[test]
    fn failure_to_decode_tcb_chain() {
        let mut root_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        root_crl.push(0);
        let (mut pem_chain, _) = pem_cert_chain();
        let mut tcb_chain = pem_chain.clone();

        // PEM's should start with "-----BEGIN CERTIFICATE-----"
        tcb_chain.insert(0, 'a');

        let mut pck_crl = include_bytes!("../data/tests/processor_crl.der").to_vec();
        pck_crl.push(0);
        let mut tcb_info = String::from("Hello");
        let mut qe_identity = String::from("World");
        let mut sgx_collateral = empty_collateral_with_version(3, 1);
        sgx_collateral.root_ca_crl = root_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = root_crl.len() as u32;
        sgx_collateral.pck_crl_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.pck_crl = pck_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = pck_crl.len() as u32;
        sgx_collateral.tcb_info_issuer_chain = tcb_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = tcb_chain.len() as u32;
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.len() as u32;
        sgx_collateral.qe_identity_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.len() as u32;

        assert_matches!(Collateral::try_from(&sgx_collateral), Err(Error::Der(_)));
    }

    #[test]
    fn failure_to_decode_tcb_info() {
        let mut root_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        root_crl.push(0);
        let mut pck_crl = include_bytes!("../data/tests/processor_crl.der").to_vec();
        let (mut pem_chain, _) = pem_cert_chain();
        pck_crl.push(0);

        // 0xFF has no assigned meaning in unicode
        let mut tcb_info = [0xFF, b'a', b'b', b'c'];

        let mut qe_identity = String::from("World");
        let mut sgx_collateral = empty_collateral_with_version(3, 1);
        sgx_collateral.root_ca_crl = root_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = root_crl.len() as u32;
        sgx_collateral.pck_crl_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.pck_crl = pck_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = pck_crl.len() as u32;
        sgx_collateral.tcb_info_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.len() as u32;
        sgx_collateral.qe_identity_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.len() as u32;

        assert_matches!(Collateral::try_from(&sgx_collateral), Err(Error::Utf8(_)));
    }

    #[test]
    fn failure_to_decode_qe_identity_chain() {
        let mut root_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        root_crl.push(0);
        let (mut pem_chain, _) = pem_cert_chain();
        let mut qe_chain = pem_chain.clone();

        // PEM's should start with "-----BEGIN CERTIFICATE-----"
        qe_chain.insert(0, 'a');

        let mut pck_crl = include_bytes!("../data/tests/processor_crl.der").to_vec();
        pck_crl.push(0);
        let mut tcb_info = String::from("Hello");
        let mut qe_identity = String::from("World");
        let mut sgx_collateral = empty_collateral_with_version(3, 1);
        sgx_collateral.root_ca_crl = root_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = root_crl.len() as u32;
        sgx_collateral.pck_crl_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.pck_crl = pck_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = pck_crl.len() as u32;
        sgx_collateral.tcb_info_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.len() as u32;
        sgx_collateral.qe_identity_issuer_chain = qe_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size = qe_chain.len() as u32;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.len() as u32;

        assert_matches!(Collateral::try_from(&sgx_collateral), Err(Error::Der(_)));
    }

    #[test]
    fn failure_to_decode_qe_identity() {
        let mut root_crl = include_bytes!("../data/tests/root_crl.der").to_vec();
        root_crl.push(0);
        let (mut pem_chain, _) = pem_cert_chain();
        let mut pck_crl = include_bytes!("../data/tests/processor_crl.der").to_vec();
        pck_crl.push(0);
        let mut tcb_info = String::from("Hello");

        // 0xFF has no assigned meaning in unicode
        let mut qe_identity = [128u8, 129, 130, 131];

        let mut sgx_collateral = empty_collateral_with_version(3, 1);
        sgx_collateral.root_ca_crl = root_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.root_ca_crl_size = root_crl.len() as u32;
        sgx_collateral.pck_crl_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.pck_crl = pck_crl.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.pck_crl_size = pck_crl.len() as u32;
        sgx_collateral.tcb_info_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.tcb_info = tcb_info.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.tcb_info_size = tcb_info.len() as u32;
        sgx_collateral.qe_identity_issuer_chain = pem_chain.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_issuer_chain_size = pem_chain.len() as u32;
        sgx_collateral.qe_identity = qe_identity.as_mut_ptr() as *mut core::ffi::c_char;
        sgx_collateral.qe_identity_size = qe_identity.len() as u32;

        assert_matches!(Collateral::try_from(&sgx_collateral), Err(Error::Utf8(_)));
    }
}
