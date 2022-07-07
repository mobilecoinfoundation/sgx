// Copyright (c) 2022 The MobileCoin Foundation

use mbedtls::{
    alloc::Box as MbedtlsBox,
    bignum::Mpi,
    ecp::EcPoint,
    hash::Type as HashType,
    pk::{EcGroup, EcGroupId, Pk},
    x509::Certificate,
};
use pem::PemError;
use sha2::{Digest, Sha256};
use std::mem::size_of;

// The size of a quote header. Table 3 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const QUOTE_HEADER_SIZE: usize = 48;

// The size of an enclave report (body). Table 5 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const ENCLAVE_REPORT_SIZE: usize = 384;

// Size of the full ECDSA signature.
// Table 6 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const SIGNATURE_SIZE: usize = 64;

// Size of one of the components of the ECDSA signature.
// Table 6 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const SIGNATURE_COMPONENT_SIZE: usize = 32;

// Size of the full ECDSA key.
// Table 7 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const KEY_SIZE: usize = 64;

// Size of one of the components of the ECDSA key.
// Table 7 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const KEY_COMPONENT_SIZE: usize = 32;

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

// The starting byte of the signature for the quote. *QE Report Signature* of
// the Quote Signature Data Structure. Table 4 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const QUOTING_ENCLAVE_REPORT_DATA_START: usize = QUOTING_ENCLAVE_REPORT_START + 320;

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

// ASN.1 Tag for an integer
const ASN1_INTEGER: u8 = 2;
// ASN.1 Tag for a sequence
const ASN1_SEQUENCE: u8 = 48;

// The byte size of the `type` and `length` fields of the ASN.1
// type-length-value stream
const ASN1_TYPE_LENGTH_SIZE: usize = 2;

/// A quote for DCAP attestation
pub struct Quote {
    bytes: Vec<u8>,
}

impl Quote {}

impl Quote {
    /// Returns a [Quote] created from the provided `bytes`.
    ///
    /// # Arguments
    ///
    /// * `bytes` the bytes of the quote as defined in
    ///     https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Quote {
            bytes: bytes.to_vec(),
        }
    }

    /// Verify the enclave report body within the quote.
    pub fn verify_enclave_report_body(&self) -> Result<(), Error> {
        let bytes = self.get_header_and_enclave_report_body();
        let mut key = self.get_pub_key().map_err(Error::Key)?;
        self.verify_signature(bytes, ISV_ENCLAVE_SIGNATURE_START, &mut key)
    }

    /// Verify the quoting enclave report within the quote.
    pub fn verify_quoting_enclave_report(&self) -> Result<(), Error> {
        let bytes = self.get_quoting_enclave_report();
        let mut certificate = self.get_pck_certificate()?;
        let key = certificate.public_key_mut();
        self.verify_signature(bytes, QUOTING_ENCLAVE_SIGNATURE_START, key)
    }

    /// Verify the attestation key in the quote is valid.
    pub fn verify_attestation_key(&self) -> Result<(), Error> {
        let mut hasher = Sha256::new();

        let key = &self.bytes[ATTESTATION_KEY_START..ATTESTATION_KEY_START + KEY_SIZE];
        hasher.update(key);

        let authentication_data = self.get_qe_authentication_data();
        hasher.update(authentication_data);

        let hash = hasher.finalize();
        let report_data = &self.bytes
            [QUOTING_ENCLAVE_REPORT_DATA_START..QUOTING_ENCLAVE_REPORT_DATA_START + hash.len()];

        if report_data == hash.as_slice() {
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

    /// Get the public signing key for the enclave report body (and header)
    fn get_pub_key(&self) -> Result<Pk, mbedtls::Error> {
        let mut start = ATTESTATION_KEY_START;
        let x = Mpi::from_binary(&self.bytes[start..start + KEY_COMPONENT_SIZE])?;
        start += KEY_COMPONENT_SIZE;
        let y = Mpi::from_binary(&self.bytes[start..start + KEY_COMPONENT_SIZE])?;
        let point = EcPoint::from_components(x, y)?;

        let secp256r1 = EcGroup::new(EcGroupId::SecP256R1)?;

        Pk::public_from_ec_components(secp256r1, point)
    }

    /// Returns the PCK certificate that was used for signing the quoting
    /// enclave report.
    /// Note: This certificate is assumed to be valid.
    fn get_pck_certificate(&self) -> Result<MbedtlsBox<Certificate>, Error> {
        //TODO this should only be looking at the `Certification Data`
        // of the `QE Certification Data`, Table 9 of
        // https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
        // However the pem crate walks over the other data nicely for initial development
        let pem = pem::parse(self.bytes.as_slice())?;
        Certificate::from_pem(&pem.contents).map_err(Error::Certificate)
    }

    /// Returns the quoting enclave report from the overall quote.
    fn get_quoting_enclave_report(&self) -> &[u8] {
        &self.bytes
            [QUOTING_ENCLAVE_REPORT_START..QUOTING_ENCLAVE_REPORT_START + ENCLAVE_REPORT_SIZE]
    }

    /// Returns the DER version of the signature.
    /// mbedtls wants a DER version of the signature, while the raw quote
    /// format has only the r and s values of the ECDSA signature
    // TODO strict DER requires an extra 0 prefix on the r value when the r
    //  value's most significant bit is set.  This is because `r` should be
    //  unsigned, but the underlying ASN.1 of DER uses an integer [signed].
    fn get_der_signature(&self, offset: usize) -> Vec<u8> {
        let mut start = offset;
        let r = &self.bytes[start..start + SIGNATURE_COMPONENT_SIZE];
        start += SIGNATURE_COMPONENT_SIZE;
        let s = &self.bytes[start..start + SIGNATURE_COMPONENT_SIZE];

        let sequence_length = ASN1_TYPE_LENGTH_SIZE + r.len() + ASN1_TYPE_LENGTH_SIZE + s.len();
        let mut signature = vec![ASN1_SEQUENCE, sequence_length as u8];
        for component in [r, s] {
            signature.extend([ASN1_INTEGER, component.len() as u8]);
            signature.extend(component);
        }
        signature
    }

    /// Returns `Ok(())` when the signature of `bytes` matches for `key`.
    ///
    /// # Arguments
    /// - `bytes` The bytes to verify the signature for.  This is the raw bytes
    ///     *not* a message digest.
    /// - `signature_offset` The byte offset to the signature in the underlying
    ///     quote structure.
    /// - `key` The key that was used to sign the `bytes`.
    fn verify_signature(
        &self,
        bytes: &[u8],
        signature_offset: usize,
        key: &mut Pk,
    ) -> Result<(), Error> {
        let signature = self.get_der_signature(signature_offset);
        let hash = Sha256::digest(bytes);
        key.verify(HashType::Sha256, &hash, &signature)
            .map_err(Error::Signature)
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Unable to load the Certificate with mbedtls
    Certificate(mbedtls::Error),

    /// Failure to parse the Pem files from the quote data
    PemParsing(PemError),

    /// Failure to verify a Signature
    Signature(mbedtls::Error),

    /// A failure to convert a binary key into an mbedtls version.
    /// This is unlikely to happen as it should only happen if there is an
    /// error in the FFI or if there is a failure to malloc.
    Key(mbedtls::Error),

    AttestationKey,
}

impl From<PemError> for Error {
    fn from(src: PemError) -> Self {
        Self::PemParsing(src)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HW_QUOTE: &[u8] = include_bytes!("../tests/data/hw_quote.dat");
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
        assert_eq!(
            quote.verify_quoting_enclave_report(),
            Err(Error::Signature(mbedtls::Error::EcpVerifyFailed))
        );
    }

    #[test]
    fn failure_to_parse_pem_certificates() {
        // TODO Once more of the quote parsing logic comes in remove hard coded
        //  value of 0x41c, based on current quote data file.
        let quote = Quote::from_bytes(&HW_QUOTE[..0x41c]);
        assert_eq!(
            quote.verify_quoting_enclave_report(),
            Err(Error::PemParsing(PemError::MalformedFraming))
        );
    }

    #[test]
    fn failure_to_load_certificate() {
        let mut bad_cert = HW_QUOTE.to_vec();
        // TODO Once more of the quote parsing logic comes in remove hard coded
        //  value of 0x440, based on current quote data file.
        bad_cert[0x440] = 0;
        let quote = Quote::from_bytes(&bad_cert);

        // Since the pem is utilized for parsing the certificates out of the
        // quote data, it fails before `Certificate::from_pem()` gets a chance
        // to fail
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
        assert_eq!(
            quote.verify_enclave_report_body(),
            Err(Error::Signature(mbedtls::Error::EcpVerifyFailed))
        );
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
}
