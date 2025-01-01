// Copyright (c) 2023-2025 The MobileCoin Foundation

//! TCB measurements for an SGX enclave.
//!
//! The TCB measurements are present as OID extensions on the leaf PCK
//! certificate. The extensions are documented in
//! <https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf>
//!
//! These TCB measurements contain the FMSPC value which can be used to query
//! for the advisories associated with these TCB values at
//! <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>.

use crate::{CertificationData, Quote3};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use const_oid::ObjectIdentifier;
use serde::{Deserialize, Serialize};
use x509_cert::attr::{AttributeTypeAndValue, AttributeValue};
use x509_cert::der::asn1::OctetStringRef;
use x509_cert::der::{Decode, DecodePem};
use x509_cert::Certificate;

/// Per <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-model-v3>
/// fmspc is limited to 12 hex characters, or 6 bytes.
pub const FMSPC_SIZE: usize = 6;

/// The number of component SVN values in the TCB info.
pub const COMPONENT_SVN_COUNT: usize = 16;

// Values from
// <https://api.trustedservices.intel.com/documents/Intel_SGX_PCK_Certificate_CRL_Spec-1.5.pdf#%5B%7B%22num%22%3A193%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C690%2C0%5D>
const SGX_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1");
const TCB_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2");
const TCB_COMPONENT_OIDS: [ObjectIdentifier; COMPONENT_SVN_COUNT] = [
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.1"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.2"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.3"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.4"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.5"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.6"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.7"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.8"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.9"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.10"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.11"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.12"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.13"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.14"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.15"),
    ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.16"),
];
const PCE_SVN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.2.17");
const FMSPC_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113741.1.13.1.4");

/// Error parsing TCB info from PCK leaf certificate
#[derive(Debug, PartialEq, displaydoc::Display, Clone, Serialize, Deserialize)]
pub enum Error {
    /// Missing the SGX OID extension: {0}
    MissingSgxExtension(String),
    /// Failed to parse TCB info: {0}
    Der(String),
    /// Expected an FMSPC size of 6 bytes, got {0}
    FmspcSize(usize),
    /// Unsupported quote certification data, should be `PckCertificateChain`
    UnsupportedQuoteCertificationData,
}

impl From<x509_cert::der::Error> for Error {
    fn from(err: x509_cert::der::Error) -> Self {
        Error::Der(err.to_string())
    }
}

// The SGX extensions aren't really documented. They aren't RFC 5280 extensions
// which are `OID` and `OCTET`. They're an `OID` and an `Any`, which is what the
// [`AttributeTypeAndValue`] is.
type SgxExtensions = Vec<AttributeTypeAndValue>;

/// The TCB info provided by the PCK(Provisioning Certification Key) leaf
/// certificate
#[derive(Debug, PartialEq)]
pub struct TcbInfo {
    svns: [u32; COMPONENT_SVN_COUNT],
    pce_svn: u32,
    fmspc: [u8; FMSPC_SIZE],
}

impl TcbInfo {
    /// Create a new instance of [`TcbInfo`]
    pub fn new(svns: [u32; COMPONENT_SVN_COUNT], pce_svn: u32, fmspc: [u8; FMSPC_SIZE]) -> Self {
        Self {
            svns,
            pce_svn,
            fmspc,
        }
    }

    /// Get the component SVN values
    pub fn svns(&self) -> &[u32; COMPONENT_SVN_COUNT] {
        &self.svns
    }

    /// Get the PCE SVN value
    pub fn pce_svn(&self) -> &u32 {
        &self.pce_svn
    }

    /// Get the FMSPC value
    pub fn fmspc(&self) -> &[u8; FMSPC_SIZE] {
        &self.fmspc
    }

    /// Get the hex representation of the FMSPC value.
    ///
    /// Useful for querying the TCB advisories from
    /// <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>
    pub fn fmspc_to_hex(&self) -> String {
        // Using the lowercase hex encoding to match the hex encoding of the
        // `signature` field in the TCB data from
        // <https://api.trustedservices.intel.com/sgx/certification/v4/tcb?fmspc={}>
        hex::encode(self.fmspc)
    }
}

impl TryFrom<&Certificate> for TcbInfo {
    type Error = Error;

    fn try_from(cert: &Certificate) -> Result<Self, Self::Error> {
        let sgx_extensions = sgx_extensions(cert)?;

        let fmspc = fmspc(&sgx_extensions)?;

        let (pce_svn, svns) = tcb_svns(&sgx_extensions)?;

        Ok(TcbInfo::new(svns, pce_svn, fmspc))
    }
}

impl<T: AsRef<[u8]>> TryFrom<&Quote3<T>> for TcbInfo {
    type Error = Error;

    fn try_from(quote: &Quote3<T>) -> Result<Self, Self::Error> {
        let signature_data = quote.signature_data();
        let certification_data = signature_data.certification_data();
        let CertificationData::PckCertificateChain(pem_chain) = certification_data else {
            return Err(Error::UnsupportedQuoteCertificationData);
        };
        let chain = pem_chain
            .into_iter()
            .map(Certificate::from_pem)
            .collect::<Result<Vec<_>, _>>()?;
        let leaf_cert = chain
            .first()
            .ok_or(Error::UnsupportedQuoteCertificationData)?;
        Self::try_from(leaf_cert)
    }
}

/// Get the [`SgxExtensions`] from the `cert`.
///
/// # Errors
/// * `Error::MissingSgxExtension` if the `cert` does not have the SGX extension.
/// * `Error::DerDecoding` if the contained DER is invalid.
fn sgx_extensions(cert: &Certificate) -> Result<SgxExtensions, Error> {
    let extensions = &cert.tbs_certificate.extensions;
    let extension = extensions
        .iter()
        .flatten()
        .find(|extension| extension.extn_id == SGX_OID)
        .ok_or_else(|| Error::MissingSgxExtension(SGX_OID.to_string()))?;

    let der_bytes = extension.extn_value.as_bytes();
    Ok(SgxExtensions::from_der(der_bytes)?)
}

/// Get the FMSPC value from the extensions
///
/// # Errors
/// * `Error::MissingSgxExtension` if the `cert` does not have the FMSPC extension.
/// * `Error::DerDecoding` if the FMSPC DER value is not an OctetString
/// * `Error::FmspcSize` if the FMSPC DER value is not exactly 6 bytes.
fn fmspc(sgx_extensions: &SgxExtensions) -> Result<[u8; FMSPC_SIZE], Error> {
    let fmspc_value = oid_value(&FMSPC_OID, sgx_extensions)?;
    let octet = fmspc_value.decode_as::<OctetStringRef>()?;
    let fmspc_bytes = octet.as_bytes();

    if fmspc_bytes.len() != FMSPC_SIZE {
        return Err(Error::FmspcSize(fmspc_bytes.len()));
    }

    let mut fmspc = [0u8; FMSPC_SIZE];
    fmspc.copy_from_slice(fmspc_bytes);
    Ok(fmspc)
}

/// Get the value for the `oid`s attribute.
///
/// # Errors
/// `Error::MissingSgxExtension` if the `oid` is not present in `extensions`.
fn oid_value(oid: &ObjectIdentifier, extensions: &SgxExtensions) -> Result<AttributeValue, Error> {
    let extension = extensions
        .iter()
        .find(|extension| &extension.oid == oid)
        .ok_or_else(|| Error::MissingSgxExtension(oid.to_string()))?;
    Ok(extension.value.clone())
}

/// Get the SVN values from the nested `TCB_OID`
///
/// # Errors
/// * `Error::MissingSgxExtension` if any of the 1-16 component SVNs or PCE SVN is missing.
/// * `Error::DerDecoding` if the SVN values fail to decode to u32s.
fn tcb_svns(sgx_extensions: &SgxExtensions) -> Result<(u32, [u32; COMPONENT_SVN_COUNT]), Error> {
    let tcb = oid_value(&TCB_OID, sgx_extensions)?;
    let components = tcb.decode_as::<SgxExtensions>()?;

    let pce_svn_value = oid_value(&PCE_SVN_OID, &components)?;
    let pce_svn = pce_svn_value.decode_as::<u32>()?;

    let mut svns = [0; COMPONENT_SVN_COUNT];
    for (i, oid) in TCB_COMPONENT_OIDS.iter().enumerate() {
        let value = oid_value(oid, &components)?;
        let svn = value.decode_as::<u32>()?;
        svns[i] = svn;
    }
    Ok((pce_svn, svns))
}

#[cfg(test)]
mod test {
    use super::*;
    use alloc::vec;
    use assert_matches::assert_matches;
    use core::mem;
    use core::ops::Range;
    use mc_sgx_dcap_sys_types::{sgx_ql_ecdsa_sig_data_t, sgx_quote3_t};
    use x509_cert::der::Tag::{BitString, OctetString};
    use x509_cert::der::{Any, Encode};
    use yare::parameterized;

    const LEAF_CERT: &[u8] = include_bytes!("../data/tests/leaf_cert.der");

    /// Get the range of bytes for the `oid` in `der_bytes`.
    ///
    /// This range includes the tag and length bytes for the OID.
    fn oid_range(oid: &ObjectIdentifier, der_bytes: &[u8]) -> Range<usize> {
        let mut oid_bytes = vec![];
        oid.encode_to_vec(&mut oid_bytes)
            .expect("failed to encode OID");
        let oid_offset = der_bytes
            .windows(oid_bytes.len())
            .position(|window| window == oid_bytes)
            .expect("Failed to find OID");

        let oid_end = oid_offset + oid_bytes.len();
        oid_offset..oid_end
    }

    /// Get the offset to the QE Certification data within the provided quote bytes
    ///
    /// The QE Certification data and its offset is defined in Table 9
    /// <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A72%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C356%2C0%5D>
    fn cert_data_offset(quote_bytes: impl AsRef<[u8]>) -> usize {
        let quote_bytes = quote_bytes.as_ref();
        let auth_data_offset =
            mem::size_of::<sgx_quote3_t>() + mem::size_of::<sgx_ql_ecdsa_sig_data_t>();
        let auth_data_size = u16::from_le_bytes([
            quote_bytes[auth_data_offset],
            quote_bytes[auth_data_offset + 1],
        ]) as usize;

        // "2" is for the u16 for reading in the auth data size
        auth_data_offset + auth_data_size + 2
    }

    #[test]
    fn valid_pck_tcb_info() {
        let certificate = Certificate::from_der(&LEAF_CERT).expect("failed to parse DER");
        let tcb_info = TcbInfo::try_from(&certificate).expect("failed to parse TCB info");

        // These were taken by looking at `leaf_cert.der` on an ASN1 decoder, like
        // <https://lapo.it/asn1js/#MIIEjzCCBDSgAwIBAgIVAPtJxlxRlleZOb_spRh9U8K7AT_3MAoGCCqGSM49BAMCMHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0yMjA2MTMyMTQ2MzRaFw0yOTA2MTMyMTQ2MzRaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj_Ee1lkGJofDX745Ks5qxqu7Mk7Mqcwkx58TCSTsabRCSvobSl_Ts8b0dltKUW3jqRd-SxnPEWJ-jUw-SpzwWaOCAqgwggKkMB8GA1UdIwQYMBaAFNDoqtp11_kuSReYPHsUZdDV8llNMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHBzOi8vYXBpLnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjMvcGNrY3JsP2NhPXByb2Nlc3NvciZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFKy9gk624HzNnDyCw7QWnhmVfE31MA4GA1UdDwEB_wQEAwIGwDAMBgNVHRMBAf8EAjAAMIIB1AYJKoZIhvhNAQ0BBIIBxTCCAcEwHgYKKoZIhvhNAQ0BAQQQ36FQl3ntUr3KUwbEFvmRGzCCAWQGCiqGSIb4TQENAQIwggFUMBAGCyqGSIb4TQENAQIBAgERMBAGCyqGSIb4TQENAQICAgERMBAGCyqGSIb4TQENAQIDAgECMBAGCyqGSIb4TQENAQIEAgEEMBAGCyqGSIb4TQENAQIFAgEBMBEGCyqGSIb4TQENAQIGAgIAgDAQBgsqhkiG-E0BDQECBwIBBjAQBgsqhkiG-E0BDQECCAIBADAQBgsqhkiG-E0BDQECCQIBADAQBgsqhkiG-E0BDQECCgIBADAQBgsqhkiG-E0BDQECCwIBADAQBgsqhkiG-E0BDQECDAIBADAQBgsqhkiG-E0BDQECDQIBADAQBgsqhkiG-E0BDQECDgIBADAQBgsqhkiG-E0BDQECDwIBADAQBgsqhkiG-E0BDQECEAIBADAQBgsqhkiG-E0BDQECEQIBCzAfBgsqhkiG-E0BDQECEgQQERECBAGABgAAAAAAAAAAADAQBgoqhkiG-E0BDQEDBAIAADAUBgoqhkiG-E0BDQEEBAYAkG7VAAAwDwYKKoZIhvhNAQ0BBQoBADAKBggqhkjOPQQDAgNJADBGAiEA1XJi0ht4hw8YtC6E4rYscp9bF-7UOhVGeKePA5TW2FQCIQCIUAaewOuWOIvstZN4V8Zu8NFCC4vFg-cZqO6QfezEaA>
        let expected_tcb_info = TcbInfo {
            svns: [17, 17, 2, 4, 1, 128, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            pce_svn: 11,
            fmspc: [0, 144, 110, 213, 0, 0],
        };
        assert_eq!(tcb_info, expected_tcb_info);
    }

    #[parameterized(
        sgx = { &SGX_OID },
        fmspc = { &FMSPC_OID },
        tcb = { &TCB_OID },
        pce_svn = { &PCE_SVN_OID },
        tcb_comp_1 = { &TCB_COMPONENT_OIDS[0] },
        tcb_comp_3 = { &TCB_COMPONENT_OIDS[2] },
        tcb_comp_16 = { &TCB_COMPONENT_OIDS[15] },
    )]
    fn missing_oid(oid: &ObjectIdentifier) {
        let mut der_bytes = LEAF_CERT.to_vec();

        let oid_range = oid_range(oid, &der_bytes);

        // Corrupts the last number of the OID value,
        // i.e. 1.2.840.113741.1.13.1.2.1 -> 1.2.840.113741.1.13.1.2.2
        der_bytes[oid_range.end - 1] += 1;

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert_eq!(
            TcbInfo::try_from(&certificate),
            Err(Error::MissingSgxExtension(oid.to_string()))
        );
    }

    #[test]
    fn malformed_sgx_extensions() {
        let mut der_bytes = LEAF_CERT.to_vec();

        let oid_range = oid_range(&TCB_OID, &der_bytes);

        // Corrupts the expected ObjectIdentifier tag
        der_bytes[oid_range.start] += 1;

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            TcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[test]
    fn malformed_fmspc() {
        let mut der_bytes = LEAF_CERT.to_vec();

        let oid_range = oid_range(&FMSPC_OID, &der_bytes);

        // Expecting OctetString tag
        der_bytes[oid_range.end] = BitString.number().value();

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            TcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[test]
    fn malformed_tcb() {
        let mut der_bytes = LEAF_CERT.to_vec();

        let oid_range = oid_range(&TCB_OID, &der_bytes);

        // Expecting Sequence tag
        der_bytes[oid_range.end] = OctetString.number().value();

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            TcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[test]
    fn malformed_pce_svn() {
        let mut der_bytes = LEAF_CERT.to_vec();

        let oid_range = oid_range(&PCE_SVN_OID, &der_bytes);

        // Expecting Integer tag
        der_bytes[oid_range.end] = OctetString.number().value();

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            TcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[parameterized(
        comp_1 = { &TCB_COMPONENT_OIDS[0] },
        comp_5 = { &TCB_COMPONENT_OIDS[4] },
        comp_16 = { &TCB_COMPONENT_OIDS[15] },
    )]
    fn malformed_tcb_component(oid: &ObjectIdentifier) {
        let mut der_bytes = LEAF_CERT.to_vec();

        let oid_range = oid_range(oid, &der_bytes);

        // Expecting Integer tag
        der_bytes[oid_range.end] = OctetString.number().value();

        let certificate = Certificate::from_der(&der_bytes).expect("failed to parse DER");
        assert!(matches!(
            TcbInfo::try_from(&certificate),
            Err(Error::Der(_))
        ));
    }

    #[test]
    fn fmspc_from_extensions() {
        // This is done low level because changing the length of the DER FMSPC
        // would require updating *all* of the DER objects which contain this
        // one.
        // This test shows that the low level setup is correct for the
        // subsequent tests that verify the error handling of incorrect FMSPC
        // length.
        let bytes = [0u8, 1, 2, 3, 4, 5];
        let fmspc_value = Any::new(OctetString, bytes).expect("Failed to build value");
        let extensions = vec![AttributeTypeAndValue {
            oid: FMSPC_OID,
            value: fmspc_value,
        }];

        assert_eq!(fmspc(&extensions), Ok(bytes));
    }

    #[test]
    fn fmspc_too_short() {
        let bytes = [0u8, 1, 2, 3, 4];
        let fmspc_value = Any::new(OctetString, bytes).expect("Failed to build value");
        let extensions = vec![AttributeTypeAndValue {
            oid: FMSPC_OID,
            value: fmspc_value,
        }];

        assert_eq!(fmspc(&extensions), Err(Error::FmspcSize(5)));
    }

    #[test]
    fn fmspc_too_long() {
        let bytes = [0u8, 1, 2, 3, 4, 5, 6];
        let fmspc_value = Any::new(OctetString, bytes).expect("Failed to build value");
        let extensions = vec![AttributeTypeAndValue {
            oid: FMSPC_OID,
            value: fmspc_value,
        }];

        assert_eq!(fmspc(&extensions), Err(Error::FmspcSize(7)));
    }

    #[parameterized(
        zero_to_five = { [0u8, 1, 2, 3, 4, 5], "000102030405" },
        // These values (e3, e5, client) were taken from
        // <https://api.trustedservices.intel.com/sgx/certification/v4/fmspcs>
        e3 = { [0, 144, 110, 213, 0, 0], "00906ed50000" },
        e5 = { [144, 192, 111, 0, 0, 0], "90c06f000000" },
        client = { [0, 128, 110, 166, 0, 0], "00806ea60000" },
    )]
    fn valid_fmspc_to_hex(fmspc: [u8; FMSPC_SIZE], expected: &str) {
        let tcb_info = TcbInfo::new([0u32; COMPONENT_SVN_COUNT], 0, fmspc);

        assert_eq!(tcb_info.fmspc_to_hex(), expected);
    }

    #[test]
    fn tcb_from_quote() {
        let hw_quote = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(hw_quote.as_ref()).expect("Failed to parse quote");
        let tcb_info = TcbInfo::try_from(&quote).expect("Failed getting tcb info from quote");

        // These were taken by looking at `leaf_cert.der` on an ASN1 decoder, like
        // <https://lapo.it/asn1js/#MIIEjzCCBDSgAwIBAgIVAPtJxlxRlleZOb_spRh9U8K7AT_3MAoGCCqGSM49BAMCMHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQGEwJVUzAeFw0yMjA2MTMyMTQ2MzRaFw0yOTA2MTMyMTQ2MzRaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj_Ee1lkGJofDX745Ks5qxqu7Mk7Mqcwkx58TCSTsabRCSvobSl_Ts8b0dltKUW3jqRd-SxnPEWJ-jUw-SpzwWaOCAqgwggKkMB8GA1UdIwQYMBaAFNDoqtp11_kuSReYPHsUZdDV8llNMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHBzOi8vYXBpLnRydXN0ZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjMvcGNrY3JsP2NhPXByb2Nlc3NvciZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFKy9gk624HzNnDyCw7QWnhmVfE31MA4GA1UdDwEB_wQEAwIGwDAMBgNVHRMBAf8EAjAAMIIB1AYJKoZIhvhNAQ0BBIIBxTCCAcEwHgYKKoZIhvhNAQ0BAQQQ36FQl3ntUr3KUwbEFvmRGzCCAWQGCiqGSIb4TQENAQIwggFUMBAGCyqGSIb4TQENAQIBAgERMBAGCyqGSIb4TQENAQICAgERMBAGCyqGSIb4TQENAQIDAgECMBAGCyqGSIb4TQENAQIEAgEEMBAGCyqGSIb4TQENAQIFAgEBMBEGCyqGSIb4TQENAQIGAgIAgDAQBgsqhkiG-E0BDQECBwIBBjAQBgsqhkiG-E0BDQECCAIBADAQBgsqhkiG-E0BDQECCQIBADAQBgsqhkiG-E0BDQECCgIBADAQBgsqhkiG-E0BDQECCwIBADAQBgsqhkiG-E0BDQECDAIBADAQBgsqhkiG-E0BDQECDQIBADAQBgsqhkiG-E0BDQECDgIBADAQBgsqhkiG-E0BDQECDwIBADAQBgsqhkiG-E0BDQECEAIBADAQBgsqhkiG-E0BDQECEQIBCzAfBgsqhkiG-E0BDQECEgQQERECBAGABgAAAAAAAAAAADAQBgoqhkiG-E0BDQEDBAIAADAUBgoqhkiG-E0BDQEEBAYAkG7VAAAwDwYKKoZIhvhNAQ0BBQoBADAKBggqhkjOPQQDAgNJADBGAiEA1XJi0ht4hw8YtC6E4rYscp9bF-7UOhVGeKePA5TW2FQCIQCIUAaewOuWOIvstZN4V8Zu8NFCC4vFg-cZqO6QfezEaA>
        let expected_tcb_info = TcbInfo {
            svns: [17, 17, 2, 4, 1, 128, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            pce_svn: 11,
            fmspc: [0, 144, 110, 213, 0, 0],
        };
        assert_eq!(tcb_info, expected_tcb_info);
    }

    #[test]
    fn tcb_from_quote_fails_for_wrong_cert_data_type() {
        let mut hw_quote = include_bytes!("../data/tests/hw_quote.dat").to_vec();

        let cert_data_offset = cert_data_offset(&hw_quote);

        // Not all types are supported so we set to 1
        // (PPID in plain text, CPUSVN and PCESVN)
        hw_quote[cert_data_offset] = 1;

        let quote = Quote3::try_from(hw_quote.as_ref()).expect("Failed to parse quote");

        assert_matches!(
            TcbInfo::try_from(&quote),
            Err(Error::UnsupportedQuoteCertificationData)
        );
    }

    #[test]
    fn tcb_from_quote_fails_for_no_certificates() {
        let mut hw_quote = include_bytes!("../data/tests/hw_quote.dat").to_vec();

        let cert_data_offset = cert_data_offset(&hw_quote);

        // 2, to skip the certification data type
        let start = cert_data_offset + 2;
        let end = start + 4;

        // Setting size to 0 bytes, so no certs
        hw_quote[start..end].copy_from_slice(&[0, 0, 0, 0]);

        let quote = Quote3::try_from(hw_quote.as_ref()).expect("Failed to parse quote");

        assert_matches!(
            TcbInfo::try_from(&quote),
            Err(Error::UnsupportedQuoteCertificationData)
        );
    }

    #[test]
    fn tcb_from_quote_fails_to_decode_certificates() {
        let mut hw_quote = include_bytes!("../data/tests/hw_quote.dat").to_vec();

        let cert_data_offset = cert_data_offset(&hw_quote);

        // 2 to skip the certification data type, 4 to skip the size
        let cert_contents_offset = cert_data_offset + 2 + 4;

        // Then we skip past the PEM header to get to a pem byte that we can change.
        let pem_byte_offset = cert_contents_offset + "-----BEGIN CERTIFICATE-----\n".len();

        // `%` is an invalid base64 character sure to make the parsing fail.
        hw_quote[pem_byte_offset] = '%' as u8;

        let quote = Quote3::try_from(hw_quote.as_ref()).expect("Failed to parse quote");

        assert_matches!(TcbInfo::try_from(&quote), Err(Error::Der(_)));
    }
}
