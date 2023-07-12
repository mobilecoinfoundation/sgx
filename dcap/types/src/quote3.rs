// Copyright (c) 2022-2023 The MobileCoin Foundation

//! This module provides types related to Quote v3

use crate::certification_data::{CertificationData, MIN_CERT_DATA_SIZE};
use crate::Quote3Error;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::mem;
use mc_sgx_core_types::{QuoteNonce, ReportBody, ReportData};
use mc_sgx_dcap_sys_types::{sgx_ql_ecdsa_sig_data_t, sgx_quote3_t, sgx_quote_header_t};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use sha2::{Digest, Sha256};
use static_assertions::const_assert;
use subtle::ConstantTimeEq;

// Most of the SGX SDK sizes are `u32` values. When being stored in higher level
// rust structures `usize` is used. This check ensures the usage of `usize` is
// ok on any platform using these types.
const_assert!(mem::size_of::<usize>() >= mem::size_of::<u32>());

// Size of the Key
const KEY_SIZE: usize = 64;

// Size of a Signature
const SIGNATURE_SIZE: usize = 64;

// The offset to the report body for the app. From the start of the quote.
const REPORT_BODY_OFFSET: usize = mem::size_of::<sgx_quote_header_t>();

// The offset to the attestation key, from the start of the quote.
const ATTESTATION_KEY_OFFSET: usize = mem::size_of::<sgx_quote3_t>() + SIGNATURE_SIZE;

// The offset to the QE report body, from the start of the quote.
const QE_REPORT_BODY_OFFSET: usize = ATTESTATION_KEY_OFFSET + KEY_SIZE;

/// The minimum size of a byte array to contain a [`AuthenticationData`]
/// the 2 bytes for QE authentication data size
const MIN_AUTH_DATA_SIZE: usize = 2;

/// The minimum size of a byte array to contain a [`SignatureData`]
const MIN_SIGNATURE_DATA_SIZE: usize =
    mem::size_of::<sgx_ql_ecdsa_sig_data_t>() + MIN_AUTH_DATA_SIZE + MIN_CERT_DATA_SIZE;

/// The minimum size of a byte array to contain a [`Quote3`]
pub const MIN_QUOTE_SIZE: usize = mem::size_of::<sgx_quote3_t>() + MIN_SIGNATURE_DATA_SIZE;

type Result<T> = ::core::result::Result<T, Quote3Error>;

/// Quote version 3
#[derive(Clone, Debug)]
pub struct Quote3<T> {
    // The full raw bytes of the Quote3 data
    raw_bytes: T,
    report_body: ReportBody,
}

impl<T: AsRef<[u8]>> Eq for Quote3<T> {}

impl<T: AsRef<[u8]>> PartialEq<Self> for Quote3<T> {
    fn eq(&self, other: &Self) -> bool {
        self.raw_bytes.as_ref().eq(other.raw_bytes.as_ref())
    }
}

impl<T: AsRef<[u8]>> PartialOrd<Self> for Quote3<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: AsRef<[u8]>> Ord for Quote3<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.raw_bytes.as_ref().cmp(other.raw_bytes.as_ref())
    }
}

impl<T: AsRef<[u8]>> Hash for Quote3<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.raw_bytes.as_ref().hash(state);
    }
}

impl<T: AsRef<[u8]>> Quote3<T> {
    /// Verify the signatures of the quote
    ///
    /// The verifying key is expected to be the public key of the PCK leaf
    /// certificate available from the
    /// [`Quote3::signature_data()`] -> [`SignatureData::certification_data()`]
    pub fn verify(&self, key: &VerifyingKey) -> Result<()> {
        let signature_data = self.signature_data();
        self.verify_qe_report(key, &signature_data)?;
        self.verify_attestation_key(&signature_data)?;
        self.verify_isv_report(&signature_data)?;
        Ok(())
    }

    /// Verify the signature of the QE report
    ///
    /// The public key can be retrieved from the PCK leaf certificate.
    fn verify_qe_report(&self, key: &VerifyingKey, signature_data: &SignatureData) -> Result<()> {
        let qe_report_end = QE_REPORT_BODY_OFFSET + mem::size_of::<ReportBody>();
        let qe_report_bytes = &self.raw_bytes.as_ref()[QE_REPORT_BODY_OFFSET..qe_report_end];
        key.verify(qe_report_bytes, &signature_data.qe_report_signature)
            .map_err(|_| Quote3Error::SignatureVerification)?;
        Ok(())
    }

    /// Verify the attestation key is valid
    ///
    /// The
    /// [ECDSA attestation key](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf#%5B%7B%22num%22%3A75%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C69%2C687%2C0%5D)
    /// is not directly part of a signed data member. In order to verify
    /// the integrity of the key we must look at the report data of the QE
    /// report. The QE report is signed and its report data contains a hash
    /// which uses the expected attestation key as one of the inputs.
    fn verify_attestation_key(&self, signature_data: &SignatureData) -> Result<()> {
        let mut hasher = Sha256::new();
        let attestation_key =
            &self.raw_bytes.as_ref()[ATTESTATION_KEY_OFFSET..ATTESTATION_KEY_OFFSET + KEY_SIZE];
        hasher.update(attestation_key);
        hasher.update(&signature_data.authentication_data);
        let hash = hasher.finalize();

        let mut data = [0u8; ReportData::SIZE];
        data[..hash.len()].copy_from_slice(hash.as_slice());

        match data
            .ct_eq(signature_data.qe_report_body().report_data().as_ref())
            .into()
        {
            true => Ok(()),
            false => Err(Quote3Error::SignatureVerification),
        }
    }

    /// Verify the ISV report
    ///
    /// The ISV(Independent Software Vendor) report is often referred to as the
    /// application enclave.
    fn verify_isv_report(&self, signature_data: &SignatureData) -> Result<()> {
        let isv_report_bytes = &self.raw_bytes.as_ref()
            [..mem::size_of::<sgx_quote_header_t>() + mem::size_of::<ReportBody>()];
        signature_data
            .attestation_key
            .verify(isv_report_bytes, &signature_data.isv_enclave_signature)
            .map_err(|_| Quote3Error::SignatureVerification)?;
        Ok(())
    }

    /// Verify the provided `nonce` matches the one in `report_data`
    ///
    /// When a nonce is passed to the quote generation, a QE report will be
    /// returned where the report data is `SHA256(nonce||quote)||32-0x00's`.
    /// This will verify that the `nonce` and this quote instance match the
    /// provided `report_data`
    ///
    /// > Note: This report data is *not* the QE report data in the quote, it is
    ///     part of the report info returned from SGX SDK quote generation.
    ///
    /// # Arguments
    /// * `nonce` - The nonce believed to be in the `report_data`
    /// * `report_data` - The report data to verify matches the `nonce` and this
    ///     quote instance.
    ///
    /// Returns `true` if the `report_data` matches the `nonce` and this quote
    /// instance.  Returns `false` if they differ.
    ///
    pub fn verify_nonce(&self, nonce: &QuoteNonce, report_data: &ReportData) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        hasher.update(&self.raw_bytes);
        let hash = hasher.finalize();

        let mut data = [0u8; ReportData::SIZE];
        data[..hash.len()].copy_from_slice(hash.as_slice());

        data.ct_eq(report_data.as_ref()).into()
    }

    /// Report body of the application enclave
    ///
    /// This is also referred to as the ISV report body.
    pub fn app_report_body(&self) -> &ReportBody {
        &self.report_body
    }

    /// Signature data of the Quote
    pub fn signature_data(&self) -> SignatureData {
        SignatureData::try_from(&self.raw_bytes.as_ref()[mem::size_of::<sgx_quote3_t>()..])
            .expect("Signature data was validated during Quote creation.")
    }

    /// Try to get a [`Quote3`] from `bytes`
    ///
    /// This will ensure `bytes` is for the correct quote type and that it's
    /// large enough to represent the quote.
    ///
    /// # Arguments:
    /// * `bytes` - The bytes to interpret as a [`Quote3`]
    ///
    /// # Errors:
    /// * [`Quote3Error::InputLength`] if the length of `bytes` is not large
    ///   enough to represent the [`Quote3`].
    /// * [`Quote3Error::Version`] if the `bytes` is for a different quote
    ///   version.
    fn try_from_bytes(bytes: T) -> Result<Self> {
        let raw_bytes = bytes;
        let bytes = raw_bytes.as_ref();
        let actual = bytes.len();
        if actual < MIN_QUOTE_SIZE {
            return Err(Quote3Error::InputLength {
                required: MIN_QUOTE_SIZE,
                actual,
            });
        }

        let (_, version) = le_u16(bytes);
        if version != 3 {
            return Err(Quote3Error::Version(version));
        }

        let report_body = ReportBody::try_from(&bytes[REPORT_BODY_OFFSET..])
            .expect("Previous check should guarantee enough size to decode ReportBody");

        let _ = SignatureData::try_from(&bytes[mem::size_of::<sgx_quote3_t>()..])
            .map_err(|e| e.increase_size(mem::size_of::<sgx_quote3_t>()))?;

        Ok(Self {
            raw_bytes,
            report_body,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for Quote3<&'a [u8]> {
    type Error = Quote3Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Self::try_from_bytes(bytes)
    }
}

#[cfg(feature = "alloc")]
impl From<Quote3<&[u8]>> for Quote3<Vec<u8>> {
    fn from(quote: Quote3<&[u8]>) -> Self {
        Self {
            raw_bytes: quote.raw_bytes.to_vec(),
            report_body: quote.report_body,
        }
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Vec<u8>> for Quote3<Vec<u8>> {
    type Error = Quote3Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from_bytes(bytes)
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Quote3<T> {
    fn as_ref(&self) -> &[u8] {
        self.raw_bytes.as_ref()
    }
}

/// Signature Data
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignatureData<'a> {
    isv_enclave_signature: Signature,
    attestation_key: VerifyingKey,
    qe_report_body: ReportBody,
    qe_report_signature: Signature,
    authentication_data: AuthenticationData<'a>,
    certification_data: CertificationData<'a>,
}

impl<'a> TryFrom<&'a [u8]> for SignatureData<'a> {
    type Error = Quote3Error;

    /// Parses [`SignatureData`] from bytes.
    ///
    /// The bytes are assumed to be the Quote Signature Data Structure defined
    /// in table 4 of
    /// <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>.
    /// They bytes are also referenced as the "Quote Signature Data" in table 2.
    ///
    /// # Errors:
    /// * [`Quote3Error::InputLength`] if the length of `bytes` is not large
    ///   enough to represent the [`SignatureData`].
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let actual = bytes.len();
        let required = MIN_SIGNATURE_DATA_SIZE;
        if actual < required {
            return Err(Quote3Error::InputLength { actual, required });
        }

        let (bytes, isv_signature) = take(SIGNATURE_SIZE)(bytes);
        let isv_enclave_signature = Signature::try_from(isv_signature)?;

        let (bytes, point_bytes) = take(KEY_SIZE)(bytes);
        let point = EncodedPoint::from_untagged_bytes(point_bytes.into());
        let attestation_key = VerifyingKey::from_encoded_point(&point)?;

        let qe_report_body = ReportBody::try_from(bytes)
            .expect("Previous check should guarantee enough size to decode ReportBody");
        let bytes = &bytes[mem::size_of::<ReportBody>()..];

        let (bytes, qe_report_signature) = take(SIGNATURE_SIZE)(bytes);
        let qe_report_signature = Signature::try_from(qe_report_signature)?;

        let authentication_data = AuthenticationData::try_from(bytes).map_err(|e| {
            // Because the authentication data is between the
            // `sgx_ql_ecdsa_sig_data_t` and the certification data, the
            // certification data needs to be accounted for in the `required`
            // while the actual is limited to the main structure and what the
            // authentication data saw.
            match e {
                Quote3Error::InputLength { actual, required } => Quote3Error::InputLength {
                    actual: actual + mem::size_of::<sgx_ql_ecdsa_sig_data_t>(),
                    required: required
                        + (mem::size_of::<sgx_ql_ecdsa_sig_data_t>() + MIN_CERT_DATA_SIZE),
                },
                error => error,
            }
        })?;

        let certification_data = CertificationData::try_from(&bytes[authentication_data.size()..])
            .map_err(|e| {
                e.increase_size(
                    mem::size_of::<sgx_ql_ecdsa_sig_data_t>() + authentication_data.size(),
                )
            })?;

        Ok(Self {
            isv_enclave_signature,
            attestation_key,
            qe_report_body,
            qe_report_signature,
            authentication_data,
            certification_data,
        })
    }
}

impl<'a> SignatureData<'a> {
    /// [`CertificationData`] of the [`SignatureData`]
    pub fn certification_data(&self) -> &CertificationData {
        &self.certification_data
    }

    /// QE(quoting enclave) [`ReportBody`] of the [`SignatureData`]
    pub fn qe_report_body(&self) -> &ReportBody {
        &self.qe_report_body
    }
}

/// The Quoting enclave authentication data
///
/// Table 8 of
/// <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AuthenticationData<'a> {
    // The `data` field as described in the QuoteLibReference.
    // The length of this *will* equal the `size` field as described in the
    // QuoteLibReference
    data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for AuthenticationData<'a> {
    type Error = Quote3Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut required = MIN_AUTH_DATA_SIZE;
        let actual = bytes.len();
        if actual < required {
            return Err(Quote3Error::InputLength { required, actual });
        }

        let (bytes, data_size_16) = le_u16(bytes);
        let data_size = data_size_16 as usize;

        required += data_size;
        if actual < required {
            Err(Quote3Error::InputLength { required, actual })
        } else {
            Ok(Self {
                data: &bytes[..data_size],
            })
        }
    }
}

impl<'a> AuthenticationData<'a> {
    pub fn size(&self) -> usize {
        self.data.len() + mem::size_of::<u16>()
    }
}

impl<'a> AsRef<[u8]> for AuthenticationData<'a> {
    fn as_ref(&self) -> &[u8] {
        self.data
    }
}

/// Read a u32 from the provided `input` stream.
///
/// It is assumed that `input` has enough bytes to contain the value
///
/// # Arguments
/// * `input` - The input stream to read the `u32` from.
///
/// # Returns
/// A tuple where the first element is the rest of the `input` stream after
/// reading the value. The second element is the `u32` value read from the input
/// stream.
pub(crate) fn le_u32(input: &[u8]) -> (&[u8], u32) {
    nom::number::complete::le_u32::<_, nom::error::Error<&[u8]>>(input)
        .expect("Size of stream should have been guaranteed to hold 4 bytes")
}

/// Read a u16 from the provided `input` stream.
///
/// It is assumed that `input` has enough bytes to contain the value
///
/// # Arguments
/// * `input` - The input stream to read the `u16` from.
///
/// # Returns
/// A tuple where the first element is the rest of the `input` stream after
/// reading the value. The second element is the `u16` value read from the input
/// stream.
pub(crate) fn le_u16(input: &[u8]) -> (&[u8], u16) {
    nom::number::complete::le_u16::<_, nom::error::Error<&[u8]>>(input)
        .expect("Size of stream should have been guaranteed to hold 2 bytes")
}

/// Take `count` bytes from an input stream
///
/// It is assumed that the input stream has `count` bytes or more.
///
/// # Arguments
/// * `count` - The number of bytes to take
///
/// # Returns
/// A function which will take `count` bytes from a stream.
/// The function returns a tuple where the first element is the rest of the
/// input stream after taking the bytes. The second element is the taken bytes.
fn take(count: usize) -> impl Fn(&[u8]) -> (&[u8], &[u8]) {
    move |input| {
        nom::bytes::complete::take::<usize, &[u8], nom::error::Error<&[u8]>>(count)(input)
            .expect("Size of stream should have been guaranteed to hold the bytes")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::slice;
    use mc_sgx_core_sys_types::sgx_report_body_t;
    use mc_sgx_core_types::CpuSvn;
    use yare::parameterized;
    extern crate alloc;
    use alloc::vec::Vec;
    use x509_cert::{der::DecodePem, Certificate};

    /// A P-256 public key uncompressed in raw bytes. This was taken from a HW
    /// quote.
    /// When decoding a key from bytes the p256 crate will validate that the
    /// point is actually on the curve, as such random made up values can not be
    /// used for tests.
    const VALID_P256_KEY: [u8; 64] = [
        122, 39, 249, 38, 29, 211, 254, 162, 54, 21, 2, 101, 53, 190, 157, 113, 112, 80, 169, 131,
        79, 185, 212, 53, 219, 66, 56, 170, 240, 215, 152, 213, 37, 30, 18, 79, 18, 75, 137, 105,
        4, 226, 244, 2, 254, 126, 45, 236, 204, 55, 251, 80, 207, 1, 98, 201, 109, 26, 87, 37, 211,
        185, 75, 109,
    ];

    /// Provides ReportData for a given quote and nonce.
    ///
    /// This is meant to mimic the `sgx_report_data_t` in the QE report that
    /// comes back in the `report_info` of `sgx_ql_get_quote()`
    ///
    /// # Arguments:
    /// * `quote` - The quote to generate the [`ReportData`] from.
    /// * `nonce` - The nonce to generate the [`ReportData`] from.
    fn report_data_from_quote_and_nonce(quote: &Quote3<&[u8]>, nonce: &QuoteNonce) -> ReportData {
        let mut report_data = [0u8; ReportData::SIZE];
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        hasher.update(quote.raw_bytes);
        let hash = hasher.finalize();
        report_data[..hash.len()].copy_from_slice(hash.as_slice());
        report_data.into()
    }

    /// Set the minimum fields in `bytes` to be interpreted as a quote3.
    ///
    /// In particular this will:
    /// - Set the version to `3`.
    /// - Put a valid public key in the signature data
    /// - Zero the tail of `bytes`.  This ensures that the dynamically sized
    ///   trailing structures show up as empty
    ///
    /// # Arguments:
    /// * `bytes` -  the bytes to update to be a valid quote structure. `bytes`
    ///   needs have a length of at least `MIN_QUOTE_SIZE`.
    ///
    /// Returns the updated version of `bytes`.
    fn quotify_bytes(bytes: &mut [u8]) -> &mut [u8] {
        let version = 3u16.to_le_bytes();
        bytes[..mem::size_of::<u16>()].copy_from_slice(&version);

        signature_datafy_bytes(&mut bytes[mem::size_of::<sgx_quote3_t>()..]);

        bytes
    }

    /// Set the minimum fields in `bytes` to be interpreted as signature data.
    ///
    /// In particular this will:
    /// - Put a valid public key in the signature data
    /// - Zero the tail of `bytes`.  This ensures that the dynamically sized
    ///   trailing structures show up as empty
    /// - Set the certification data type to 1. 0 is invalid.
    ///
    /// # Arguments:
    /// * `bytes` -  the bytes to update to be a valid signature data. `bytes`
    ///   needs have a length of at least `MIN_SIGNATURE_DATA_SIZE`.
    ///
    /// Returns the updated version of `bytes`.
    fn signature_datafy_bytes(bytes: &mut [u8]) -> &mut [u8] {
        let key_offset = SIGNATURE_SIZE;
        let key_end = key_offset + KEY_SIZE;
        bytes[key_offset..key_end].copy_from_slice(&VALID_P256_KEY);
        bytes[mem::size_of::<sgx_ql_ecdsa_sig_data_t>()..].fill(0);
        bytes[mem::size_of::<sgx_ql_ecdsa_sig_data_t>() + MIN_AUTH_DATA_SIZE] = 1;

        bytes
    }

    #[allow(unsafe_code)]
    fn ecdsa_sig_to_bytes(body: sgx_ql_ecdsa_sig_data_t) -> [u8; MIN_SIGNATURE_DATA_SIZE] {
        // SAFETY: This is a test only function. The size of `body` is used for
        // reinterpretation of `body` into a byte slice. The slice is copied
        // from prior to the leaving of this function ensuring the raw pointer
        // is not persisted.
        let alias_bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                &body as *const sgx_ql_ecdsa_sig_data_t as *const u8,
                mem::size_of::<sgx_ql_ecdsa_sig_data_t>(),
            )
        };
        let mut bytes: [u8; MIN_SIGNATURE_DATA_SIZE] = [0; MIN_SIGNATURE_DATA_SIZE];

        // 0 is an invalid certification data type, so default to 1
        bytes[mem::size_of::<sgx_ql_ecdsa_sig_data_t>() + MIN_AUTH_DATA_SIZE] = 1;

        bytes[..mem::size_of::<sgx_ql_ecdsa_sig_data_t>()].copy_from_slice(alias_bytes);
        bytes
    }

    // Get the signing key from the PCK leaf certificate in the
    // [`CertifciationData`] of the `quote`.
    fn pck_leaf_signing_key<T: AsRef<[u8]>>(quote: &Quote3<T>) -> VerifyingKey {
        let signature_data = quote.signature_data();
        let cert_chain = match signature_data.certification_data() {
            CertificationData::PckCertificateChain(cert_chain) => cert_chain,
            _ => panic!("expected a PckCertChain"),
        };
        let leaf_pem = cert_chain.into_iter().collect::<Vec<_>>()[0];

        let certificate = Certificate::from_pem(leaf_pem).expect("failed to parse PEM");
        let key = VerifyingKey::from_sec1_bytes(
            certificate
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .as_bytes()
                .expect("Failed to parse public key"),
        )
        .expect("Failed to decode public key");
        key
    }

    #[test]
    fn quote_from_slice() {
        const REPORT_BODY_SIZE: usize = mem::size_of::<ReportBody>();
        const SIGNATURE_DATA_OFFSET: usize = mem::size_of::<sgx_quote3_t>();
        let app_report_body_bytes = [5u8; REPORT_BODY_SIZE];
        let qe_report_body_bytes = [7u8; REPORT_BODY_SIZE];
        let ecdsa_sig = sgx_ql_ecdsa_sig_data_t {
            sig: [6u8; SIGNATURE_SIZE],
            attest_pub_key: VALID_P256_KEY,
            qe_report: ReportBody::try_from(qe_report_body_bytes.as_slice())
                .unwrap()
                .into(),
            qe_report_sig: [8u8; SIGNATURE_SIZE],
            // __IncompleteArrayField so can only be empty(default)
            auth_certification_data: Default::default(),
        };
        let signature_bytes = ecdsa_sig_to_bytes(ecdsa_sig);

        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());

        bytes[REPORT_BODY_OFFSET..REPORT_BODY_OFFSET + REPORT_BODY_SIZE]
            .copy_from_slice(&app_report_body_bytes);
        bytes[SIGNATURE_DATA_OFFSET..SIGNATURE_DATA_OFFSET + MIN_SIGNATURE_DATA_SIZE]
            .copy_from_slice(&signature_bytes);
        let quote = Quote3::try_from(bytes.as_ref()).unwrap();
        assert_eq!(quote.raw_bytes, bytes);
        assert_eq!(
            quote.app_report_body(),
            &ReportBody::try_from(app_report_body_bytes.as_slice()).unwrap()
        );
        assert_eq!(
            quote.signature_data(),
            SignatureData::try_from(signature_bytes.as_slice()).unwrap()
        );
    }

    #[test]
    fn quote_from_real_quote_file() {
        let hw_quote = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(hw_quote.as_ref()).unwrap();

        assert_eq!(quote.raw_bytes, hw_quote);
        let signature_data = quote.signature_data();

        let cert_chain = match signature_data.certification_data() {
            CertificationData::PckCertificateChain(cert_chain) => cert_chain,
            _ => panic!("expected a PckCertChain"),
        };

        // 3 for Root CA, Intermediate CA, and the PCK cert
        let pems = cert_chain.into_iter().collect::<Vec<_>>();
        assert_eq!(pems.len(), 3);
    }

    #[parameterized(
    version_2 = {2},
    version_4 = {4},
    )]
    fn quote_with_wrong_version(version: u16) {
        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());

        let version_bytes = version.to_le_bytes();
        bytes[..mem::size_of::<u16>()].copy_from_slice(&version_bytes);

        assert_eq!(
            Quote3::try_from(bytes.as_ref()),
            Err(Quote3Error::Version(version))
        );
    }

    #[test]
    fn quote_too_small_for_signature() {
        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        assert_eq!(
            Quote3::try_from(&bytes[..bytes.len() - 1]),
            Err(Quote3Error::InputLength {
                required: MIN_QUOTE_SIZE,
                actual: MIN_QUOTE_SIZE - 1
            })
        );
    }

    #[test]
    fn quote_too_small_for_signature_trailing_contents() {
        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());

        // the u16 to get passed the certification data type
        let cert_data_size_offset = (MIN_QUOTE_SIZE - MIN_CERT_DATA_SIZE) + mem::size_of::<u16>();
        bytes[cert_data_size_offset] = 1;

        assert_eq!(
            Quote3::try_from(&bytes[..]),
            Err(Quote3Error::InputLength {
                actual: MIN_QUOTE_SIZE,
                required: MIN_QUOTE_SIZE + 1,
            })
        );
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn quote_fails_to_decode_attestation_key() {
        let mut hw_quote = include_bytes!("../data/tests/hw_quote.dat").to_vec();
        hw_quote[mem::size_of::<sgx_quote3_t>() + SIGNATURE_SIZE] += 1;
        assert_eq!(Quote3::try_from(hw_quote), Err(Quote3Error::Ecdsa));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn quote_from_vec() {
        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        let quote: Quote3<Vec<u8>> = bytes.to_vec().try_into().unwrap();
        assert_eq!(quote.raw_bytes, bytes);
    }

    #[test]
    fn valid_quote_nonce_1_succeeds() {
        let mut binding = [3u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        let quote = bytes.as_ref().try_into().unwrap();
        let nonce = [1u8; QuoteNonce::SIZE].into();
        let report_data = report_data_from_quote_and_nonce(&quote, &nonce);
        assert_eq!(quote.verify_nonce(&nonce, &report_data), true);
    }

    #[test]
    fn valid_quote_nonce_5_succeeds() {
        let mut binding = [8u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        let quote = bytes.as_ref().try_into().unwrap();
        let nonce = [5u8; QuoteNonce::SIZE].into();
        let report_data = report_data_from_quote_and_nonce(&quote, &nonce);
        assert_eq!(quote.verify_nonce(&nonce, &report_data), true);
    }

    #[test]
    fn quote_nonce_off_by_one_fails() {
        let mut binding = [8u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        let quote = bytes.as_ref().try_into().unwrap();
        let mut nonce = [5u8; QuoteNonce::SIZE].into();
        let report_data = report_data_from_quote_and_nonce(&quote, &nonce);

        let contents: &mut [u8] = nonce.as_mut();
        contents[0] += 1;

        assert_eq!(quote.verify_nonce(&nonce, &report_data), false);
    }

    #[test]
    fn trailing_report_data_non_zero_fails() {
        let mut binding = [8u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        let quote = bytes.as_ref().try_into().unwrap();
        let nonce = [5u8; QuoteNonce::SIZE].into();
        let mut report_data = report_data_from_quote_and_nonce(&quote, &nonce);

        let contents: &mut [u8] = report_data.as_mut();
        let hash_size = 32;
        contents[hash_size] += 1;

        assert_eq!(quote.verify_nonce(&nonce, &report_data), false);
    }

    #[test]
    fn zero_authentication_data() {
        let bytes = [0u8; MIN_AUTH_DATA_SIZE];
        let authentication_data = AuthenticationData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(authentication_data.data, []);
    }

    #[test]
    fn one_byte_authentication_data() {
        let mut bytes = [6u8; MIN_AUTH_DATA_SIZE + 1];

        // Little endian u16 size across 2 bytes
        bytes[0] = 1;
        bytes[1] = 0;

        let authentication_data = AuthenticationData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(authentication_data.data, [6]);
    }

    #[test]
    fn multiple_byte_authentication_data() {
        let mut bytes = [3u8; MIN_AUTH_DATA_SIZE + 20];

        // Little endian u16 size across 2 bytes
        bytes[0] = 5;
        bytes[1] = 0;

        let authentication_data = AuthenticationData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(authentication_data.data, [3u8; 5]);
    }

    #[test]
    fn authentication_data_less_than_min() {
        let bytes = [0u8; MIN_AUTH_DATA_SIZE - 1];
        assert_eq!(
            AuthenticationData::try_from(bytes.as_slice()),
            Err(Quote3Error::InputLength {
                actual: MIN_AUTH_DATA_SIZE - 1,
                required: MIN_AUTH_DATA_SIZE
            })
        );
    }

    #[test]
    fn authentication_data_to_small_for_data() {
        let mut bytes = [0u8; MIN_AUTH_DATA_SIZE];

        bytes[0] = 1;

        assert_eq!(
            AuthenticationData::try_from(bytes.as_slice()),
            Err(Quote3Error::InputLength {
                actual: MIN_AUTH_DATA_SIZE,
                required: MIN_AUTH_DATA_SIZE + 1
            })
        );
    }

    #[test]
    fn signature_data_1() {
        let mut report_body = sgx_report_body_t::default();
        report_body.cpu_svn = CpuSvn::try_from([2u8; CpuSvn::SIZE]).unwrap().into();
        let ecdsa_sig = sgx_ql_ecdsa_sig_data_t {
            sig: [1u8; SIGNATURE_SIZE],
            attest_pub_key: VALID_P256_KEY,
            qe_report: report_body,
            qe_report_sig: [3u8; SIGNATURE_SIZE],
            // __IncompleteArrayField so can only be empty(default)
            auth_certification_data: Default::default(),
        };
        let bytes = ecdsa_sig_to_bytes(ecdsa_sig);

        let signature_data = SignatureData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(
            signature_data.isv_enclave_signature,
            Signature::try_from([1u8; 64].as_slice()).unwrap()
        );

        // `VerifyingKey::try_from` wants sec1 encoded data.
        // From https://www.secg.org/sec1-v2.pdf Section 2.3.3, uncompressed is
        // stored as `04 || X || Y`.
        let mut sec1_key: [u8; 65] = [0u8; 65];
        sec1_key[0] = 4;
        sec1_key[1..].copy_from_slice(VALID_P256_KEY.as_slice());
        assert_eq!(
            signature_data.attestation_key,
            VerifyingKey::try_from(sec1_key.as_slice()).unwrap()
        );
        assert_eq!(signature_data.qe_report_body(), &report_body.into());
        assert_eq!(
            signature_data.qe_report_signature,
            Signature::try_from([3u8; 64].as_slice()).unwrap()
        );
        assert_eq!(signature_data.authentication_data.data, []);
        assert_eq!(signature_data.certification_data().raw_data(), []);
    }

    #[test]
    fn signature_data_2() {
        let mut report_body = sgx_report_body_t::default();
        report_body.cpu_svn = CpuSvn::try_from([3u8; CpuSvn::SIZE]).unwrap().into();
        let ecdsa_sig = sgx_ql_ecdsa_sig_data_t {
            sig: [2u8; SIGNATURE_SIZE],
            attest_pub_key: VALID_P256_KEY,
            qe_report: report_body,
            qe_report_sig: [4u8; SIGNATURE_SIZE],
            // __IncompleteArrayField so can only be empty(default)
            auth_certification_data: Default::default(),
        };
        let bytes = ecdsa_sig_to_bytes(ecdsa_sig);

        let signature_data = SignatureData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(
            signature_data.isv_enclave_signature,
            Signature::try_from([2u8; 64].as_slice()).unwrap()
        );

        let mut sec1_key: [u8; 65] = [0u8; 65];
        sec1_key[0] = 4;
        sec1_key[1..].copy_from_slice(VALID_P256_KEY.as_slice());
        assert_eq!(
            signature_data.attestation_key,
            VerifyingKey::try_from(sec1_key.as_slice()).unwrap()
        );
        assert_eq!(signature_data.qe_report_body(), &report_body.into());
        assert_eq!(
            signature_data.qe_report_signature,
            Signature::try_from([4u8; 64].as_slice()).unwrap()
        );
        assert_eq!(signature_data.authentication_data.data, []);
        assert_eq!(signature_data.certification_data().raw_data(), []);
    }

    #[test]
    fn signature_data_less_than_min() {
        let bytes = [2u8; MIN_SIGNATURE_DATA_SIZE - 1];
        assert_eq!(
            SignatureData::try_from(bytes.as_slice()),
            Err(Quote3Error::InputLength {
                actual: MIN_SIGNATURE_DATA_SIZE - 1,
                required: MIN_SIGNATURE_DATA_SIZE,
            })
        );
    }

    #[test]
    fn signature_data_with_auth_data() {
        let mut binding = [2u8; MIN_SIGNATURE_DATA_SIZE + 3];
        let bytes = signature_datafy_bytes(binding.as_mut_slice());

        let mut start = mem::size_of::<sgx_ql_ecdsa_sig_data_t>();
        let size = 3;
        bytes[start] = size;
        start += mem::size_of::<u16>();
        let end = start + size as usize;
        bytes[start..end].fill(20);

        let cert_data_type = 1;
        bytes[end] = cert_data_type;

        // Test focuses on the auth parsing, so only spot checking one field
        // of SignatureData
        let signature_data = SignatureData::try_from(bytes.as_ref()).unwrap();
        assert_eq!(
            signature_data.qe_report_signature,
            Signature::try_from([2u8; 64].as_slice()).unwrap()
        );
        assert_eq!(signature_data.authentication_data.data, [20, 20, 20]);
    }

    #[test]
    fn signature_data_without_room_for_auth_data() {
        let mut binding = [2u8; MIN_SIGNATURE_DATA_SIZE];
        let bytes = signature_datafy_bytes(binding.as_mut_slice());

        let auth_offset = mem::size_of::<sgx_ql_ecdsa_sig_data_t>();
        // Need to make the size big enough to also consume the potential
        // CertificationData
        let auth_data_size = MIN_CERT_DATA_SIZE + 1;
        bytes[auth_offset] = auth_data_size as u8;

        assert_eq!(
            SignatureData::try_from(bytes.as_ref()),
            Err(Quote3Error::InputLength {
                actual: MIN_SIGNATURE_DATA_SIZE,
                required: MIN_SIGNATURE_DATA_SIZE + auth_data_size,
            })
        );
    }

    #[test]
    fn signature_data_with_certification_data() {
        let mut binding = [7u8; MIN_SIGNATURE_DATA_SIZE + 2];
        let bytes = signature_datafy_bytes(binding.as_mut_slice());

        let mut start = mem::size_of::<sgx_ql_ecdsa_sig_data_t>();
        // the u16 to get passed the certification data type
        start += MIN_AUTH_DATA_SIZE + mem::size_of::<u16>();
        let size = 2;
        bytes[start] = size;
        start += mem::size_of::<u32>();
        let end = start + size as usize;
        bytes[start..end].fill(11);

        // Test focuses on the cert parsing, so only spot checking one field
        // of SignatureData
        let signature_data = SignatureData::try_from(bytes.as_ref()).unwrap();
        assert_eq!(
            signature_data.qe_report_signature,
            Signature::try_from([7u8; 64].as_slice()).unwrap()
        );
        assert_eq!(signature_data.certification_data().raw_data(), [11, 11]);
    }

    #[test]
    fn signature_data_without_room_for_cert_data() {
        let mut binding = [7u8; MIN_SIGNATURE_DATA_SIZE + 1];
        let bytes = signature_datafy_bytes(binding.as_mut_slice());

        // Throw some auth data to ensure required size is computed correctly
        let mut start = mem::size_of::<sgx_ql_ecdsa_sig_data_t>();
        bytes[start] = 1;
        start += 1; // skip over the data byte

        // the extra u16 to get passed the certification data type
        start += MIN_AUTH_DATA_SIZE + mem::size_of::<u16>();
        bytes[start] = 1;

        assert_eq!(
            SignatureData::try_from(bytes.as_ref()),
            Err(Quote3Error::InputLength {
                actual: MIN_SIGNATURE_DATA_SIZE + 1,
                required: MIN_SIGNATURE_DATA_SIZE + 2,
            })
        );
    }

    #[test]
    fn signature_data_with_auth_and_cert_data() {
        let mut binding = [7u8; MIN_SIGNATURE_DATA_SIZE + 20];
        let bytes = signature_datafy_bytes(binding.as_mut_slice());

        // Auth data
        let mut start = mem::size_of::<sgx_ql_ecdsa_sig_data_t>();
        let size = 5;
        bytes[start] = size;
        start += mem::size_of::<u16>();
        let end = start + size as usize;
        bytes[start..end].fill(14);

        start = end;
        let data_type = 1;
        bytes[start] = data_type;

        start = end + mem::size_of::<u16>();
        let size = 4;
        bytes[start] = size;
        start += mem::size_of::<u32>();
        let end = start + size as usize;
        bytes[start..end].fill(23);

        // Test focuses on the cert parsing, so only spot checking one field
        // of SignatureData
        let signature_data = SignatureData::try_from(bytes.as_ref()).unwrap();
        assert_eq!(
            signature_data.qe_report_signature,
            Signature::try_from([7u8; 64].as_slice()).unwrap()
        );
        assert_eq!(signature_data.authentication_data.data, [14u8; 5]);
        assert_eq!(signature_data.certification_data().raw_data(), [23u8; 4]);
    }

    #[test]
    fn verify_quote_signature() {
        let hw_quote = include_bytes!("../data/tests/hw_quote.dat");
        let quote = Quote3::try_from(hw_quote.as_ref()).expect("Failed to parse quote");
        let key = pck_leaf_signing_key(&quote);

        assert_eq!(quote.verify(&key), Ok(()));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn quote_verification_fails_for_bad_qe_report() {
        let mut hw_quote = include_bytes!("../data/tests/hw_quote.dat").to_vec();
        hw_quote[QE_REPORT_BODY_OFFSET] += 1;
        let quote = Quote3::try_from(hw_quote).expect("Failed to parse quote");
        let key = pck_leaf_signing_key(&quote);

        assert_eq!(quote.verify(&key), Err(Quote3Error::SignatureVerification));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn quote_verification_fails_for_bad_attestation_key() {
        let mut hw_quote = include_bytes!("../data/tests/hw_quote.dat").to_vec();

        // To ensure the bad attestation key decodes correctly we'll use the
        // leaf PCK key.
        let quote = Quote3::try_from(hw_quote.clone()).expect("Failed to parse quote");
        let key = pck_leaf_signing_key(&quote);

        // From https://www.secg.org/sec1-v2.pdf Section 2.3.3, uncompressed
        // sec1 is stored as `04 || X || Y`, but the quote only stores `X || Y`.
        let point = key.to_encoded_point(false);
        let key_bytes = &point.as_bytes()[1..];

        let key_start = mem::size_of::<sgx_quote3_t>() + SIGNATURE_SIZE;
        let key_end = key_start + KEY_SIZE;
        hw_quote[key_start..key_end].copy_from_slice(key_bytes);

        let quote = Quote3::try_from(hw_quote).expect("Failed to parse quote");

        assert_eq!(quote.verify(&key), Err(Quote3Error::SignatureVerification));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn quote_verification_fails_for_isv_report() {
        let mut hw_quote = include_bytes!("../data/tests/hw_quote.dat").to_vec();
        hw_quote[REPORT_BODY_OFFSET] += 1;
        let quote = Quote3::try_from(hw_quote).expect("Failed to parse quote");
        let key = pck_leaf_signing_key(&quote);

        assert_eq!(quote.verify(&key), Err(Quote3Error::SignatureVerification));
    }
}
