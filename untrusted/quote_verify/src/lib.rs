// Copyright (c) 2022 The MobileCoin Foundation

use displaydoc::Display;
use p256::{
    ecdsa::{signature::Verifier, Error as ecdsaError, Signature, VerifyingKey},
    pkcs8::{spki::Error as spkiError, DecodePublicKey},
    EncodedPoint,
};
use sha2::{Digest, Sha256};
use std::mem::size_of;
use x509_parser::{
    error::{PEMError, X509Error},
    pem::{self, Pem},
};

/// The root signing CA
const ROOT_CERT_PEM: &[u8] = include_bytes!("../data/DCAPCACert.pem");

// The size of a quote header. Table 3 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const QUOTE_HEADER_SIZE: usize = 48;

// The size of an enclave report (body). Table 5 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const ENCLAVE_REPORT_SIZE: usize = 384;

// The size of the report data in an enclave report. *Report Data* of
// the Enclave Report Body. Table 5 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const ENCLAVE_REPORT_DATA_SIZE: usize = 64;

// Size of the full ECDSA signature.
// Table 6 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const SIGNATURE_SIZE: usize = 64;

// Size of the full ECDSA key.
// Table 7 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const KEY_SIZE: usize = 64;

// The starting byte of the signature for the *ISV Enclave Report Signature* of
// the Quote Signature Data Structure. Table 4 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// Note: the 4 is the for the *Quote Signature Data Len* from table 2.  The
// variable length is _after_ the signature.
const ISV_ENCLAVE_SIGNATURE_START: usize = QUOTE_HEADER_SIZE + ENCLAVE_REPORT_SIZE + 4;

// The starting byte of the key for the *ECDSA Attestation Key* of
// the Quote Signature Data Structure. Table 4 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const ATTESTATION_KEY_START: usize = ISV_ENCLAVE_SIGNATURE_START + SIGNATURE_SIZE;

// The starting byte of the quote report.  The *QE Report* member of the Quote
// Signature Data Structure.  Table 4 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const QUOTING_ENCLAVE_REPORT_START: usize = ATTESTATION_KEY_START + KEY_SIZE;

// The starting byte of the signature for the quote. *QE Report Signature* of
// the Quote Signature Data Structure. Table 4 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const QUOTING_ENCLAVE_SIGNATURE_START: usize = QUOTING_ENCLAVE_REPORT_START + ENCLAVE_REPORT_SIZE;

// The starting byte of the report data from the quote report. *Report Data* of
// the Enclave Report Body. Table 5 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const QUOTING_ENCLAVE_REPORT_DATA_START: usize = QUOTING_ENCLAVE_REPORT_START + 320;

// The size of the message digest in the quoting enclave report data.  See
// description of *QE Report* in table 4 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const QUOTING_ENCLAVE_REPORT_DATA_DIGEST_SIZE: usize = 32;

// The starting byte of the quoting enclave authentication data size for the
// quote.
// *Size* from Table 8 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// which comes from the *QE Authentication Data* of the Quote Signature Data
// Structure in Table 4.
const QUOTING_ENCLAVE_AUTHENTICATION_DATA_SIZE_START: usize =
    QUOTING_ENCLAVE_SIGNATURE_START + SIGNATURE_SIZE;

// The starting byte of the quoting enclave authentication data for the quote.
// *Data* from Table 8 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// which comes from the *QE Authentication Data* of the Quote Signature Data
// Structure in Table 4.
const QUOTING_ENCLAVE_AUTHENTICATION_DATA_START: usize =
    QUOTING_ENCLAVE_AUTHENTICATION_DATA_SIZE_START + 2;

// TODO Should be looking up the certification data instead of hardcoding
//  offset, To be fixed with #25
// The starting byte of the certification data for the quote.
// *Certification Data* from Table 9 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// which comes from the *QE Certification Data* of the Quote Signature Data
// Structure in Table 4.
const QUOTING_ENCLAVE_CERTIFICATION_DATA_START: usize = 0x41C;

/// A quote for DCAP attestation
pub struct Quote {
    bytes: Vec<u8>,
}

impl Quote {
    /// Returns a [Quote] created from the provided `bytes`.
    ///
    /// # Arguments
    ///
    /// * `bytes` the bytes of the quote as defined in https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Quote {
            bytes: bytes.to_vec(),
        }
    }

    pub fn verify_certificate_chain(&self) -> Result<(), Error> {
        let (_, pem) = pem::parse_x509_pem(ROOT_CERT_PEM)?;
        let root_cert = pem.parse_x509()?;

        let pems =
            Pem::iter_from_buffer(&self.bytes[QUOTING_ENCLAVE_CERTIFICATION_DATA_START..])
                .collect::<Result<Vec<_>, _>>()?;

        // Certs have a lifetime dependent on `pems` so must create them once
        // the pems are held in place.
        let mut certs = pems.iter().map(|p|{
            p.parse_x509()
        }).collect::<Result<Vec<_>, _>>()?;

        // Certs are in order from leaf -> .. -> root.  We need to start
        // verifying from the root.
        certs.reverse();

        let mut key = root_cert.public_key();
        for cert in certs.iter() {
            cert.verify_signature(Some(&key))?;
            key = cert.public_key();
        }
        Ok(())
    }

    /// Verify the enclave report body within the quote.
    pub fn verify_enclave_report_body(&self) -> Result<(), Error> {
        let bytes = self.get_header_and_enclave_report_body();
        let key = self.get_attestation_key()?;
        self.verify_signature(bytes, ISV_ENCLAVE_SIGNATURE_START, &key)
    }

    /// Verify the quoting enclave report within the quote.
    pub fn verify_quoting_enclave_report(&self) -> Result<(), Error> {
        let bytes = self.get_quoting_enclave_report();
        let pem = self.get_pck_pem()?;
        let cert = pem.parse_x509()?;
        let key = VerifyingKey::from_public_key_der(cert.public_key().raw)?;
        self.verify_signature(bytes, QUOTING_ENCLAVE_SIGNATURE_START, &key)
    }

    /// Verify the attestation key in the quote is valid.
    pub fn verify_attestation_key(&self) -> Result<(), Error> {
        let mut hasher = Sha256::new();

        let key = &self.bytes[ATTESTATION_KEY_START..ATTESTATION_KEY_START + KEY_SIZE];
        hasher.update(key);

        let authentication_data = self.get_qe_authentication_data();
        hasher.update(authentication_data);

        let hash = hasher.finalize();
        let start = QUOTING_ENCLAVE_REPORT_DATA_START;
        let end = start + QUOTING_ENCLAVE_REPORT_DATA_DIGEST_SIZE;
        let report_data = &self.bytes[start..end];

        let start = end;
        let end = QUOTING_ENCLAVE_REPORT_DATA_START + ENCLAVE_REPORT_DATA_SIZE;
        let zero_pad_after = self.bytes[start..end]
            == [0; (ENCLAVE_REPORT_DATA_SIZE - QUOTING_ENCLAVE_REPORT_DATA_DIGEST_SIZE)];

        if report_data == hash.as_slice() && zero_pad_after {
            Ok(())
        } else {
            Err(Error::AttestationKey)
        }
    }

    fn get_qe_authentication_data(&self) -> &[u8] {
        let size_bytes = &self.bytes[QUOTING_ENCLAVE_AUTHENTICATION_DATA_SIZE_START
            ..QUOTING_ENCLAVE_AUTHENTICATION_DATA_SIZE_START + size_of::<u16>()];
        let data_length = u16::from_le_bytes(
            size_bytes
                .try_into()
                .expect("The data length should be 2 bytes"),
        ) as usize;

        &self.bytes[QUOTING_ENCLAVE_AUTHENTICATION_DATA_START
            ..QUOTING_ENCLAVE_AUTHENTICATION_DATA_START + data_length]
    }

    /// Gets the quote header and enclave report body.
    fn get_header_and_enclave_report_body(&self) -> &[u8] {
        &self.bytes[..QUOTE_HEADER_SIZE + ENCLAVE_REPORT_SIZE]
    }

    /// Get the signature verifying key for the enclave report body (and header)
    fn get_attestation_key(&self) -> Result<VerifyingKey, Error> {
        let point = EncodedPoint::from_untagged_bytes(
            self.bytes[ATTESTATION_KEY_START..ATTESTATION_KEY_START + KEY_SIZE].into(),
        );
        VerifyingKey::from_encoded_point(&point).map_err(|e| Error::Key(e.to_string()))
    }

    /// Returns the Pem version of the PCK certificate that was used for signing
    /// the quoting enclave report.
    /// Note: The certificate is assumed to be valid.
    fn get_pck_pem(&self) -> Result<Pem, Error> {
        let (_, pem) =
            pem::parse_x509_pem(&self.bytes[QUOTING_ENCLAVE_CERTIFICATION_DATA_START..])?;
        Ok(pem)
    }

    /// Returns the quoting enclave report from the overall quote.
    fn get_quoting_enclave_report(&self) -> &[u8] {
        &self.bytes
            [QUOTING_ENCLAVE_REPORT_START..QUOTING_ENCLAVE_REPORT_START + ENCLAVE_REPORT_SIZE]
    }

    /// Returns `Ok(())` when the signature of `bytes` matches for `key`.
    ///
    /// # Arguments
    /// - `bytes` The bytes to verify the signature for.  This is the raw bytes
    ///   *not* a message digest.
    /// - `signature_offset` The byte offset to the signature in the underlying
    ///   quote structure.
    /// - `key` The key that was used to sign the `bytes`.
    fn verify_signature(
        &self,
        bytes: &[u8],
        signature_offset: usize,
        key: &VerifyingKey,
    ) -> Result<(), Error> {
        let signature =
            Signature::try_from(&self.bytes[signature_offset..signature_offset + SIGNATURE_SIZE])?;
        Ok(key.verify(bytes, &signature)?)
    }
}

#[derive(Display, Debug, PartialEq, Eq)]
/// Error from verifying a Quote
pub enum Error {
    /// Unable to validate certificate used in signing
    Certificate(String),

    /// Failure to parse the Pem files from the quote data
    PemParsing(String),

    /// Failure to verify a Signature
    Signature(String),

    /// A failure to convert a binary key into an elliptical_curve version.
    Key(String),

    /// Invalid attestation key in quote
    AttestationKey,
}

impl From<ecdsaError> for Error {
    fn from(src: ecdsaError) -> Self {
        Self::Signature(src.to_string())
    }
}

impl From<spkiError> for Error {
    fn from(src: spkiError) -> Self {
        Self::Signature(src.to_string())
    }
}

impl From<X509Error> for Error {
    fn from(src: X509Error) -> Self {
        Self::Certificate(src.to_string())
    }
}

impl From<x509_parser::nom::Err<X509Error>> for Error {
    fn from(src: x509_parser::nom::Err<X509Error>) -> Self {
        Self::PemParsing(src.to_string())
    }
}

impl From<x509_parser::nom::Err<PEMError>> for Error {
    fn from(src: x509_parser::nom::Err<PEMError>) -> Self {
        Self::PemParsing(src.to_string())
    }
}

impl From<PEMError> for Error {
    fn from(src: PEMError) -> Self {
        Self::PemParsing(src.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HW_QUOTE: &[u8] = include_bytes!("../tests/data/hw_quote.dat");

    /// Returns the PEM Certificate of the `der` contents.
    ///
    /// #Arguments:
    /// * `der` - The der version of a certificate to convert to PEM format
    fn pem_certificate(der: &[u8]) -> String {
        let encoded = base64::encode(der);
        let pem_certificate = format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            encoded
        );
        pem_certificate
    }

    /// Returns the PEMs in `chain` as individual Strings per pem.
    /// # Arguments:
    /// * `chain` - Contiguous bytes representing a cert chain as PEMs.
    fn extract_pems(chain: &[u8]) -> Vec<String> {
        let pems = Pem::iter_from_buffer(chain)
            .map(|p| {
                let pem = p.unwrap();
                pem_certificate(&pem.contents)
            })
            .collect::<Vec<_>>();

        pems
    }

    #[test]
    fn verify_valid_quote_report() {
        let quote = Quote::from_bytes(HW_QUOTE);
        assert!(quote.verify_quoting_enclave_report().is_ok());
    }

    #[test]
    fn invalid_quote_report() {
        let mut bad_quote = HW_QUOTE.to_vec();
        bad_quote[QUOTING_ENCLAVE_REPORT_START + 1] = 0;
        let quote = Quote::from_bytes(&bad_quote);
        assert!(matches!(
            quote.verify_quoting_enclave_report(),
            Err(Error::Signature(_))
        ));
    }

    #[test]
    fn failure_to_parse_pem_certificates() {
        let quote = Quote::from_bytes(&HW_QUOTE[..QUOTING_ENCLAVE_CERTIFICATION_DATA_START]);
        assert!(matches!(
            quote.verify_quoting_enclave_report(),
            Err(Error::PemParsing(_))
        ));
    }

    #[test]
    fn failure_to_load_certificate() {
        let mut bad_cert = HW_QUOTE.to_vec();
        // TODO Once more of the quote parsing logic comes in remove hard coded
        //  value of 0x440, based on current quote data file. To be fixed with
        //  #25
        bad_cert[0x440] = 0;
        let quote = Quote::from_bytes(&bad_cert);

        assert!(matches!(
            quote.verify_quoting_enclave_report(),
            Err(Error::PemParsing(_))
        ));
    }

    #[test]
    fn verify_valid_enclave_report_body() {
        let quote = Quote::from_bytes(HW_QUOTE);
        assert!(quote.verify_enclave_report_body().is_ok());
    }

    #[test]
    fn failed_signature_for_enclave_report_body() {
        let mut quote = Quote::from_bytes(HW_QUOTE);
        quote.bytes[ISV_ENCLAVE_SIGNATURE_START] = 1;
        assert!(matches!(
            quote.verify_enclave_report_body(),
            Err(Error::Signature(_))
        ));
    }

    #[test]
    fn failed_to_load_attestation_key_for_enclave_report() {
        let mut identity = [0; KEY_SIZE];
        let mut quote = Quote::from_bytes(HW_QUOTE);

        quote.bytes[ATTESTATION_KEY_START..ATTESTATION_KEY_START + KEY_SIZE]
            .swap_with_slice(&mut identity);

        assert!(matches!(
            quote.verify_enclave_report_body(),
            Err(Error::Key(_))
        ));
    }

    #[test]
    fn verify_valid_attestation_key() {
        let quote = Quote::from_bytes(HW_QUOTE);
        assert!(quote.verify_attestation_key().is_ok());
    }

    #[test]
    fn invalid_attestation_key() {
        let mut quote = Quote::from_bytes(HW_QUOTE);
        quote.bytes[ATTESTATION_KEY_START] = 1;
        assert_eq!(quote.verify_attestation_key(), Err(Error::AttestationKey));
    }

    #[test]
    fn no_trailing_zeros_after_quote_report_data_digest() {
        let mut quote = Quote::from_bytes(HW_QUOTE);
        quote.bytes[QUOTING_ENCLAVE_REPORT_DATA_START + QUOTING_ENCLAVE_REPORT_DATA_DIGEST_SIZE] =
            1;
        assert_eq!(quote.verify_attestation_key(), Err(Error::AttestationKey));
    }

    #[test]
    fn no_trailing_zeros_at_end_of_quote_report_data_digest() {
        let mut quote = Quote::from_bytes(HW_QUOTE);
        quote.bytes[QUOTING_ENCLAVE_REPORT_DATA_START + (ENCLAVE_REPORT_DATA_SIZE - 1)] = 1;
        assert_eq!(quote.verify_attestation_key(), Err(Error::AttestationKey));
    }

    #[test]
    fn verify_valid_certificate_chain() {
        let quote = Quote::from_bytes(HW_QUOTE);
        assert!(quote.verify_certificate_chain().is_ok());
    }

    #[test]
    fn invalid_certificate_chain_fails() {
        let mut hw_quote = HW_QUOTE.to_vec();
        let pem_contents = hw_quote
            .drain(QUOTING_ENCLAVE_CERTIFICATION_DATA_START..)
            .collect::<Vec<_>>();
        let pems = extract_pems(pem_contents.as_slice());

        hw_quote.extend(pems[0].as_bytes());
        // Skipping the intermediate cert to force a signing chain error
        hw_quote.extend(pems[2].as_bytes());

        let quote = Quote::from_bytes(hw_quote.as_slice());
        assert!(matches!(
            quote.verify_certificate_chain(),
            Err(Error::Certificate(_))
        ));
    }

    #[test]
    fn bad_pem_file_in_cert_chain() {
        let mut hw_quote = HW_QUOTE.to_vec();
        let pem_contents = hw_quote
            .drain(QUOTING_ENCLAVE_CERTIFICATION_DATA_START..)
            .collect::<Vec<_>>();
        let mut pems = extract_pems(pem_contents.as_slice());

        // 'A' isn't significant, just a value inserted in the middle that
        // should force an error state
        let middle = pems[1].len() / 2;
        pems[1].insert(middle, 'A');

        hw_quote.extend(pems.join("").as_bytes());

        let quote = Quote::from_bytes(hw_quote.as_slice());
        assert!(matches!(
            quote.verify_certificate_chain(),
            Err(Error::PemParsing(_))
        ));
    }

    #[test]
    fn bad_der_representation_in_cert_chain() {
        let mut hw_quote = HW_QUOTE.to_vec();

        let pem_contents = hw_quote
            .drain(QUOTING_ENCLAVE_CERTIFICATION_DATA_START..)
            .collect::<Vec<_>>();
        let mut pems = extract_pems(pem_contents.as_slice());

        let (_, pem) = pem::parse_x509_pem(pems[2].as_bytes()).unwrap();
        let mut der_contents = pem.contents.clone();

        // '3' isn't significant, just a value inserted in the middle that
        // should force an error state
        der_contents.insert(der_contents.len() / 2, b'3');
        pems[2] = pem_certificate(&der_contents);

        hw_quote.extend(pems.join("").as_bytes());

        let quote = Quote::from_bytes(hw_quote.as_slice());
        assert!(matches!(
            quote.verify_certificate_chain(),
            Err(Error::PemParsing(_))
        ));
    }
}
