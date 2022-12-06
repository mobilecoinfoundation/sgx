// Copyright (c) 2022 The MobileCoin Foundation

//! This module provides types related to Quote v3

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::mem;
use mc_sgx_core_types::{QuoteNonce, ReportBody, ReportData};
use mc_sgx_dcap_sys_types::{sgx_ql_ecdsa_sig_data_t, sgx_quote3_t, sgx_quote_header_t};
use p256::ecdsa;
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

/// The minimum size of a byte array to contain a [`AuthenticationData`]
/// the 2 bytes for QE authentication data size
const MIN_AUTH_DATA_SIZE: usize = 2;

/// The minimum size of a byte array to contain a [`CertificationData`]
/// The 2(type) + 4(size) for QE certification data
const MIN_CERT_DATA_SIZE: usize = 6;

/// The minimum size of a byte array to contain a [`SignatureData`]
const MIN_SIGNATURE_DATA_SIZE: usize =
    mem::size_of::<sgx_ql_ecdsa_sig_data_t>() + MIN_AUTH_DATA_SIZE + MIN_CERT_DATA_SIZE;

/// The minimum size of a byte array to contain a [`Quote3`]
pub const MIN_QUOTE_SIZE: usize = mem::size_of::<sgx_quote3_t>() + MIN_SIGNATURE_DATA_SIZE;

/// Errors interacting with a Quote3
#[derive(Clone, Debug, displaydoc::Display, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Error {
    /** Quote buffer too small; actual size: {actual}, required size
     * {required} */
    #[allow(missing_docs)]
    InputLength { required: usize, actual: usize },
    /// Invalid quote version: {0}, should be: 3
    Version(u16),
    /// Failure to convert from bytes to ECDSA types
    Ecdsa,
}

impl Error {
    /// Increase any and all size values in the Error.
    /// Errors without a size field will be returned unmodified.  For example
    /// [`Error::Version`] will not be modified by this function even though it
    /// has a numeric value.
    fn increase_size(self, increase: usize) -> Self {
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

impl From<ecdsa::Error> for Error {
    fn from(_: ecdsa::Error) -> Self {
        // ecdsa::Error is opaque, and only provides additional information via `std::Error` impl.
        Error::Ecdsa
    }
}

type Result<T> = ::core::result::Result<T, Error>;

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
    pub fn app_report_body(&self) -> &ReportBody {
        &self.report_body
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
    /// * [`Error::InvalidInputLength`] if the length of `bytes` is not large
    ///   enough to represent the [`Quote3`].
    /// * [`Error::InvalidVersion`] if the `bytes` is for a different quote
    ///   version.
    fn try_from_bytes(bytes: T) -> Result<Self> {
        let raw_bytes = bytes;
        let bytes = raw_bytes.as_ref();
        let actual = bytes.len();
        if actual < MIN_QUOTE_SIZE {
            return Err(Error::InputLength {
                required: MIN_QUOTE_SIZE,
                actual,
            });
        }

        let (_, version) = le_u16(bytes);
        if version != 3 {
            return Err(Error::Version(version));
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
    type Error = Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        Self::try_from_bytes(bytes)
    }
}

#[cfg(feature = "alloc")]
impl TryFrom<Vec<u8>> for Quote3<Vec<u8>> {
    type Error = Error;

    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::try_from_bytes(bytes)
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
    type Error = Error;

    /// Parses [`SignatureData`] from bytes.
    ///
    /// The bytes are assumed to be the Quote Signature Data Structure defined
    /// in table 4 of
    /// <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>.
    /// They bytes are also referenced as the "Quote Signature Data" in table 2.
    ///
    /// # Errors:
    /// * [`Error::InputLength`] if the length of `bytes` is not large enough to
    ///   represent the [`SignatureData`].
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let actual = bytes.len();
        let required = MIN_SIGNATURE_DATA_SIZE;
        if actual < required {
            return Err(Error::InputLength { actual, required });
        }

        let (bytes, isv_signature) = take(SIGNATURE_SIZE)(bytes);
        let isv_enclave_signature = Signature::try_from(isv_signature)?;

        let (bytes, point_bytes) = take(KEY_SIZE)(bytes);
        let point = EncodedPoint::from_untagged_bytes(point_bytes.into());
        let attestation_key = VerifyingKey::from_encoded_point(&point).unwrap();

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
                Error::InputLength { actual, required } => Error::InputLength {
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
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let mut required = MIN_AUTH_DATA_SIZE;
        let actual = bytes.len();
        if actual < required {
            return Err(Error::InputLength { required, actual });
        }

        let (bytes, data_size_16) = le_u16(bytes);
        let data_size = data_size_16 as usize;

        required += data_size;
        if actual < required {
            Err(Error::InputLength { required, actual })
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

/// The Quoting enclave certification data
///
/// Table 9 of
/// <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CertificationData<'a> {
    // The `Certification Data` field as described in the QuoteLibReference.
    // The length of this *will* equal the `size` field as described in the
    // QuoteLibReference
    data: &'a [u8],
    // The `Certification Data Type` field as described in the
    // QuoteLibReference.
    data_type: u16,
}

impl<'a> TryFrom<&'a [u8]> for CertificationData<'a> {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let actual = bytes.len();

        let mut required = MIN_CERT_DATA_SIZE;

        if actual < required {
            return Err(Error::InputLength { required, actual });
        }

        // These shouldn't fail since we ensured the length up above
        let (bytes, data_type) = le_u16(bytes);
        let (bytes, data_size_32) = le_u32(bytes);
        let data_size = data_size_32 as usize;

        required += data_size;
        if actual < required {
            Err(Error::InputLength { required, actual })
        } else {
            Ok(Self {
                data: &bytes[..data_size],
                data_type,
            })
        }
    }
}

impl<'a> IntoIterator for &'a CertificationData<'a> {
    type Item = &'a [u8];
    type IntoIter = PemIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PemIterator {
            pem_data: self.data,
        }
    }
}

const BEGIN_PEM: &[u8] = b"-----BEGIN ";
const END_PEM: &[u8] = b"-----END ";

struct PemIterator<'a> {
    pem_data: &'a [u8],
}

/// Iterator over each PEM in a provided buffer.
impl<'a> Iterator for PemIterator<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.pem_data.is_empty() {
            return None;
        }

        let mut label: &[u8] = b"";
        let mut start = None;
        let mut offset = 0;

        // The data comes across the wire and should only use "\n" and thus
        // won't be platform specific
        let lines = self.pem_data.split_inclusive(|e| *e == b'\n');
        for line in lines {
            match start {
                None => {
                    if line.starts_with(BEGIN_PEM) {
                        start = Some(offset);
                        label = &line[BEGIN_PEM.len()..];
                    }
                }
                Some(start) => {
                    if line.starts_with(END_PEM) {
                        // In the unlikely event there is an end footer exposed
                        // with a different label we walk over, just like if
                        // there happens to be a nested begin.
                        if &line[END_PEM.len()..] == label {
                            let end = offset + line.len();
                            let pem = &self.pem_data[start..end];
                            self.pem_data = &self.pem_data[end..];
                            return Some(pem);
                        }
                    }
                }
            }
            offset += line.len();
        }
        None
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
fn le_u32(input: &[u8]) -> (&[u8], u32) {
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
fn le_u16(input: &[u8]) -> (&[u8], u16) {
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
        bytes[..mem::size_of::<sgx_ql_ecdsa_sig_data_t>()].copy_from_slice(alias_bytes);
        bytes
    }

    #[test]
    fn quote_from_slice() {
        const REPORT_BODY_SIZE: usize = mem::size_of::<ReportBody>();
        let report_body_bytes = [5u8; REPORT_BODY_SIZE];

        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());

        bytes[REPORT_BODY_OFFSET..REPORT_BODY_OFFSET + REPORT_BODY_SIZE]
            .copy_from_slice(&report_body_bytes);
        let quote = Quote3::try_from(bytes.as_ref()).unwrap();
        assert_eq!(quote.raw_bytes, bytes);
        assert_eq!(
            quote.app_report_body(),
            &ReportBody::try_from(report_body_bytes.as_slice()).unwrap()
        );
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
            Err(Error::Version(version))
        );
    }

    #[test]
    fn quote_too_small_for_signature() {
        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        assert_eq!(
            Quote3::try_from(&bytes[..bytes.len() - 1]),
            Err(Error::InputLength {
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
            Err(Error::InputLength {
                actual: MIN_QUOTE_SIZE,
                required: MIN_QUOTE_SIZE + 1,
            })
        );
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
            Err(Error::InputLength {
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
            Err(Error::InputLength {
                actual: MIN_AUTH_DATA_SIZE,
                required: MIN_AUTH_DATA_SIZE + 1
            })
        );
    }

    #[test]
    fn zero_certification_data() {
        let bytes = [0u8; MIN_CERT_DATA_SIZE];
        let certification_data = CertificationData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(certification_data.data_type, 0);
        assert_eq!(certification_data.data, []);
    }

    #[test]
    fn one_byte_certification_data() {
        let mut bytes = [8u8; MIN_CERT_DATA_SIZE + 1];

        // Little endian u16 type across 2 bytes
        bytes[0] = 2;
        bytes[1] = 0;

        // Little endian u32 size across 4 bytes
        bytes[2] = 1;
        bytes[3] = 0;
        bytes[4] = 0;
        bytes[5] = 0;

        let certification_data = CertificationData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(certification_data.data_type, 2);
        assert_eq!(certification_data.data, [8]);
    }

    #[test]
    fn multiple_byte_certification_data() {
        let mut bytes = [4u8; MIN_CERT_DATA_SIZE + 30];

        // Little endian u16 type across 2 bytes
        bytes[0] = 3;
        bytes[1] = 0;

        // Little endian u32 size across 4 bytes
        bytes[2] = 7;
        bytes[3] = 0;
        bytes[4] = 0;
        bytes[5] = 0;

        let certification_data = CertificationData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(certification_data.data_type, 3);
        assert_eq!(certification_data.data, [4u8; 7]);
    }

    #[test]
    fn certification_data_less_than_min() {
        let bytes = [0u8; MIN_CERT_DATA_SIZE - 1];
        assert_eq!(
            CertificationData::try_from(bytes.as_slice()),
            Err(Error::InputLength {
                actual: MIN_CERT_DATA_SIZE - 1,
                required: MIN_CERT_DATA_SIZE
            })
        );
    }

    #[test]
    fn certification_data_to_small_for_data() {
        let mut bytes = [0u8; MIN_CERT_DATA_SIZE];
        bytes[2] = 1;
        assert_eq!(
            CertificationData::try_from(bytes.as_slice()),
            Err(Error::InputLength {
                actual: MIN_CERT_DATA_SIZE,
                required: MIN_CERT_DATA_SIZE + 1
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
        assert_eq!(signature_data.qe_report_body, report_body.into(),);
        assert_eq!(
            signature_data.qe_report_signature,
            Signature::try_from([3u8; 64].as_slice()).unwrap()
        );
        assert_eq!(signature_data.authentication_data.data, []);
        assert_eq!(signature_data.certification_data.data, []);
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
        assert_eq!(signature_data.qe_report_body, report_body.into());
        assert_eq!(
            signature_data.qe_report_signature,
            Signature::try_from([4u8; 64].as_slice()).unwrap()
        );
        assert_eq!(signature_data.authentication_data.data, []);
        assert_eq!(signature_data.certification_data.data, []);
    }

    #[test]
    fn signature_data_less_than_min() {
        let bytes = [2u8; MIN_SIGNATURE_DATA_SIZE - 1];
        assert_eq!(
            SignatureData::try_from(bytes.as_slice()),
            Err(Error::InputLength {
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
            Err(Error::InputLength {
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
        assert_eq!(signature_data.certification_data.data, [11, 11]);
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
            Err(Error::InputLength {
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

        // cert data, skip over the data type
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
        assert_eq!(signature_data.certification_data.data, [23u8; 4]);
    }

    const LEAF_CERT: &str = "
        -----BEGIN CERTIFICATE-----
        MIIEjzCCBDSgAwIBAgIVAPtJxlxRlleZOb/spRh9U8K7AT/3MAoGCCqGSM49BAMC
        MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK
        DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
        BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0yMjA2MTMyMTQ2MzRaFw0yOTA2MTMyMTQ2
        MzRaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV
        BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG
        A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
        j/Ee1lkGJofDX745Ks5qxqu7Mk7Mqcwkx58TCSTsabRCSvobSl/Ts8b0dltKUW3j
        qRd+SxnPEWJ+jUw+SpzwWaOCAqgwggKkMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY
        PHsUZdDV8llNMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHBzOi8vYXBpLnRydXN0ZWRz
        ZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjMvcGNrY3JsP2Nh
        PXByb2Nlc3NvciZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFKy9gk624HzNnDyCw7QW
        nhmVfE31MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMIIB1AYJKoZIhvhN
        AQ0BBIIBxTCCAcEwHgYKKoZIhvhNAQ0BAQQQ36FQl3ntUr3KUwbEFvmRGzCCAWQG
        CiqGSIb4TQENAQIwggFUMBAGCyqGSIb4TQENAQIBAgERMBAGCyqGSIb4TQENAQIC
        AgERMBAGCyqGSIb4TQENAQIDAgECMBAGCyqGSIb4TQENAQIEAgEEMBAGCyqGSIb4
        TQENAQIFAgEBMBEGCyqGSIb4TQENAQIGAgIAgDAQBgsqhkiG+E0BDQECBwIBBjAQ
        BgsqhkiG+E0BDQECCAIBADAQBgsqhkiG+E0BDQECCQIBADAQBgsqhkiG+E0BDQEC
        CgIBADAQBgsqhkiG+E0BDQECCwIBADAQBgsqhkiG+E0BDQECDAIBADAQBgsqhkiG
        +E0BDQECDQIBADAQBgsqhkiG+E0BDQECDgIBADAQBgsqhkiG+E0BDQECDwIBADAQ
        BgsqhkiG+E0BDQECEAIBADAQBgsqhkiG+E0BDQECEQIBCzAfBgsqhkiG+E0BDQEC
        EgQQERECBAGABgAAAAAAAAAAADAQBgoqhkiG+E0BDQEDBAIAADAUBgoqhkiG+E0B
        DQEEBAYAkG7VAAAwDwYKKoZIhvhNAQ0BBQoBADAKBggqhkjOPQQDAgNJADBGAiEA
        1XJi0ht4hw8YtC6E4rYscp9bF+7UOhVGeKePA5TW2FQCIQCIUAaewOuWOIvstZN4
        V8Zu8NFCC4vFg+cZqO6QfezEaA==
        -----END CERTIFICATE-----
        ";

    const INTERMEDIATE_CA: &str = "
        -----BEGIN CERTIFICATE-----
        MIICmDCCAj6gAwIBAgIVANDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC
        MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD
        b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw
        CQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHExIzAh
        BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl
        bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB
        MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q+NMp2IOg
        tdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDzXnVTAT2ZhDCifyIuJwvN3wNBp9i
        HBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww
        UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl
        cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFNDo
        qtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
        AQH/AgEAMAoGCCqGSM49BAMCA0gAMEUCIQCJgTbtVqOyZ1m3jqiAXM6QYa6r5sWS
        4y/G7y8uIJGxdwIgRqPvBSKzzQagBLQq5s5A70pdoiaRJ8z/0uDz4NgV91k=
        -----END CERTIFICATE-----
        ";

    const ROOT_CA: &str = "
        -----BEGIN CERTIFICATE-----
        MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
        aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
        cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
        BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
        A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
        aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
        AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
        1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
        uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
        MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
        ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
        Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
        KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
        AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
        -----END CERTIFICATE-----
        ";

    #[test]
    fn iterate_over_a_empty_certification_data() {
        let cert_data = [0u8; MIN_CERT_DATA_SIZE];
        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let cert_iter = certification_data.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert!(certs.is_empty());
    }

    #[test]
    fn iterate_over_one_pem() {
        let raw_cert = textwrap::dedent(LEAF_CERT);
        let cert = raw_cert.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = cert.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(cert);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let cert_iter = certification_data.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert_eq!(certs, &[cert]);
    }

    #[test]
    fn iterate_over_a_cert_chain() {
        let mut cert_chain = Vec::new();
        cert_chain.push(5); // Concatenated PCK Cert Chain
        cert_chain.push(0);

        let mut size = 0;
        let pems = [LEAF_CERT, INTERMEDIATE_CA, ROOT_CA]
            .iter()
            .map(|p| textwrap::dedent(p))
            .collect::<Vec<_>>();
        let pem_bytes = pems
            .iter()
            .map(|p| p.trim_start().as_bytes())
            .collect::<Vec<_>>();
        for pem in &pem_bytes {
            size += pem.len();
            cert_chain.extend(*pem);
        }

        let size_32 = size as u32;
        let size_bytes = size_32.to_le_bytes();
        cert_chain.splice(2..2, size_bytes);

        let certification_data = CertificationData::try_from(cert_chain.as_slice()).unwrap();
        let cert_iter = certification_data.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert_eq!(certs, pem_bytes);
    }

    #[test]
    fn iterate_over_a_partial_pem_is_none() {
        let partial_pem = "
            -----BEGIN CERTIFICATE-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            ";
        let raw_pem = textwrap::dedent(partial_pem);
        let pem = raw_pem.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = pem.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(pem);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let cert_iter = certification_data.into_iter();
        assert!(cert_iter.collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn iterate_over_a_malformed_pem() {
        // The logic brings out a pem from begin to end, it's up to the decoder
        // that uses the pem to fail parsing it.
        let funky_pem = "
            -----BEGIN CERTIFICATE-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            -----BEGIN CERTIFICATE-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            -----END CERTIFICATE-----
            ";
        let raw_pem = textwrap::dedent(funky_pem);
        let pem = raw_pem.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = pem.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(pem);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let cert_iter = certification_data.into_iter();
        assert_eq!(cert_iter.collect::<Vec<_>>(), [pem]);
    }

    #[test]
    fn iterate_over_an_unmatched_nested_end() {
        // the middle end has a different label so will be treated as part of
        // the body.
        let funky_pem = "
            -----BEGIN CERTIFICATE-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            -----END SOMETHING-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            -----END CERTIFICATE-----
            ";
        let raw_pem = textwrap::dedent(funky_pem);
        let pem = raw_pem.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = pem.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(pem);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let cert_iter = certification_data.into_iter();
        assert_eq!(cert_iter.collect::<Vec<_>>(), [pem]);
    }

    #[test]
    fn iterate_over_a_non_certificate_pem() {
        // Showing the iterator doesn't care what the pem is
        // Generated via
        // ```
        // openssl ecparam -name prime256v1 -genkey -out private-key.pem
        // openssl ec -in private-key.pem -pubout -out public-key.pem
        // ```
        let pem = "
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEusf6HZYngTI8XRXWlsQk3EwXbdd5
            2GlcHz8b0Y8b2qgyKDsKkL0j70cej1n7oMcqc+FKTVAa12QpFYSiaHJvGQ==
            -----END PUBLIC KEY-----
        ";

        let raw_key = textwrap::dedent(pem);
        let key = raw_key.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = key.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(key);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let cert_iter = certification_data.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert_eq!(certs, &[key]);
    }

    #[test]
    fn ignore_contents_before_between_and_after_pems() {
        let padding_text = b"Some padding text\n";
        let mut cert_chain = Vec::new();
        cert_chain.push(5); // Concatenated PCK Cert Chain
        cert_chain.push(0);

        let mut size = 0;
        size += padding_text.len();
        cert_chain.extend(padding_text);

        let pems = [LEAF_CERT, INTERMEDIATE_CA, ROOT_CA]
            .iter()
            .map(|p| textwrap::dedent(p))
            .collect::<Vec<_>>();
        let pem_bytes = pems
            .iter()
            .map(|p| p.trim_start().as_bytes())
            .collect::<Vec<_>>();
        for pem in &pem_bytes {
            size += pem.len();
            cert_chain.extend(*pem);
            size += padding_text.len();
            cert_chain.extend(padding_text);
        }

        let size_32 = size as u32;
        let size_bytes = size_32.to_le_bytes();
        cert_chain.splice(2..2, size_bytes);

        let certification_data = CertificationData::try_from(cert_chain.as_slice()).unwrap();
        let cert_iter = certification_data.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert_eq!(certs, pem_bytes);
    }
}
