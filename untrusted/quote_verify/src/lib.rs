// Copyright (c) 2022 The MobileCoin Foundation

use mbedtls::alloc::Box as MbedtlsBox;
use mbedtls::hash::Type as HashType;
use mbedtls::x509::Certificate;
use pem::PemError;
use sha2::{Digest, Sha256};

// THe size of an enclave report (body). Table 5 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const ENCLAVE_REPORT_SIZE: usize = 384;

// Size of one of the components of the ECDSA signature.
// Table 6 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const SIGNATURE_COMPONENT_SIZE: usize = 32;

// The starting byte of the quote report.  The *QE Report* member of the Quote
// Signature Data Structure.  Table 4 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
// TODO as more of the quote structure is brought in, derive the start by summation
//  of previous type/member sizes.
const QUOTING_ENCLAVE_REPORT_START: usize = 0x234;

// The starting byte of the signature for the quote. *QE Report Signature* of
// the Quote Signature Data Structure. Table 4 of
// https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
const QUOTING_ENCLAVE_SIGNATURE_START: usize = QUOTING_ENCLAVE_REPORT_START + ENCLAVE_REPORT_SIZE;

// ASN.1 Tag for an integer
const ASN1_INTEGER: u8 = 2;
// ASN.1 Tag for a sequence
const ASN1_SEQUENCE: u8 = 48;

/// A quote for DCAP attestation
pub struct Quote {
    bytes: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    /// Unable to load the Certificate with mbedtls
    Certificate(mbedtls::Error),
    /// Failure to parse the Pem files from the quote data
    PemParsing(PemError),
    /// Failure to verify a Signature
    Signature(mbedtls::Error),
}

impl From<PemError> for Error {
    fn from(src: PemError) -> Self {
        Self::PemParsing(src)
    }
}

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

    /// Verify the quoting enclave within the report.
    pub fn verify_quoting_enclave_report(&self) -> Result<(), Error> {
        let signature = self.get_ans1_signature();
        let report = self.get_quoting_enclave_report();
        let hash = Sha256::digest(report);
        let mut cert = self.get_pck_certificate()?;
        cert.public_key_mut()
            .verify(HashType::Sha256, &hash, &signature)
            .map_err(Error::Signature)
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

    /// Returns the ASN.1 version of the signature.
    /// mbedtls wants an ASN.1 version of the signature, while the raw quote
    /// format has only the r and s values of the ECDSA signature
    fn get_ans1_signature(&self) -> Vec<u8> {
        let mut start = QUOTING_ENCLAVE_SIGNATURE_START;
        let r = &self.bytes[start..start + SIGNATURE_COMPONENT_SIZE];
        start += SIGNATURE_COMPONENT_SIZE;
        let s = &self.bytes[start..start + SIGNATURE_COMPONENT_SIZE];

        // The `2`s are the tag byte + length byte
        let length = 2 + r.len() + 2 + s.len();
        let mut signature = vec![ASN1_SEQUENCE, length as u8];
        for component in [r, s] {
            signature.extend([ASN1_INTEGER, component.len() as u8]);
            signature.extend(component);
        }
        signature
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
}
