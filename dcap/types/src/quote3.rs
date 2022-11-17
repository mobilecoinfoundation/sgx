// Copyright (c) 2022 The MobileCoin Foundation

//! This module provides types related to Quote v3

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::cmp::Ordering;
use core::hash::{Hash, Hasher};
use core::mem;
use mc_sgx_core_types::{QuoteNonce, ReportBody, ReportData};
use mc_sgx_dcap_sys_types::{sgx_ql_ecdsa_sig_data_t, sgx_quote3_t, sgx_quote_header_t};
use nom::number::complete::{le_u16, le_u32};
use sha2::{Digest, Sha256};
use static_assertions::const_assert;
use subtle::ConstantTimeEq;

// Most of the SGX SDK sizes are `u32` values. When being stored in higher level
// rust structures `usize` is used. This check ensures the usage of `usize` is
// ok on any platform using these types.
const_assert!(mem::size_of::<usize>() >= mem::size_of::<u32>());

// The size of the quote bytes. Not including the authentication or
// certification data.
const QUOTE_SIZE: usize =
    mem::size_of::<sgx_quote3_t>() + mem::size_of::<sgx_ql_ecdsa_sig_data_t>();

// The offset to the authentication data
const AUTH_DATA_OFFSET: usize = QUOTE_SIZE;

// The offset to the report body for the app. From the start of the quote.
const REPORT_BODY_OFFSET: usize = mem::size_of::<sgx_quote_header_t>();

/// The minimum size of a byte array to contain a [`AuthenticationData`]
/// the 2 bytes for QE authentication data size
const MIN_AUTH_DATA_SIZE: usize = 2;

/// The minimum size of a byte array to contain a [`CertificationData`]
/// The 2(type) + 4(size) for QE certification data
const MIN_CERT_DATA_SIZE: usize = 6;

/// The minimum size of a byte array to contain a [`Quote3`]
pub const MIN_QUOTE_SIZE: usize = mem::size_of::<sgx_quote3_t>()
    + mem::size_of::<sgx_ql_ecdsa_sig_data_t>()
    + MIN_AUTH_DATA_SIZE
    + MIN_CERT_DATA_SIZE;

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

// Using a from nom::Err that panics because of nom's generic implementation.
// Without it all of the nom calls would need to specify the type like:
// ```rust
//  let (bytes, value) = le_u16::<_, nom::error::Error<&[u8]>>(bytes)
//      .expect("Should have been prevented by previous size check.");
// ```
impl From<nom::Err<nom::error::Error<&[u8]>>> for Error {
    fn from(_: nom::Err<nom::error::Error<&[u8]>>) -> Self {
        panic!("Nom errors should be prevented by size checks when parsing a Quote3");
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
        let bytes_length = bytes.len();
        if bytes_length < MIN_QUOTE_SIZE {
            return Err(Error::InputLength {
                required: MIN_QUOTE_SIZE,
                actual: bytes_length,
            });
        }

        let (_, version) = le_u16(bytes)?;
        if version != 3 {
            return Err(Error::Version(version));
        }

        // Similar to above this shouldn't fail since we checked for `MIN_QUOTE_SIZE` above.
        let report_body =
            ReportBody::try_from(&bytes[REPORT_BODY_OFFSET..]).map_err(|_| Error::InputLength {
                required: MIN_QUOTE_SIZE,
                actual: bytes_length,
            })?;

        let auth_data = AuthenticationData::try_from(&bytes[AUTH_DATA_OFFSET..])
            .map_err(|e| e.increase_size(QUOTE_SIZE))?;

        let quote_with_auth_size = QUOTE_SIZE + auth_data.size();

        let _ = CertificationData::try_from(&bytes[quote_with_auth_size..])
            .map_err(|e| e.increase_size(quote_with_auth_size))?;

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

        let (bytes, data_size_16) = le_u16(bytes)?;
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
        let (bytes, data_type) = le_u16(bytes)?;
        let (bytes, data_size_32) = le_u32(bytes)?;
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

#[cfg(test)]
mod test {
    use super::*;
    use yare::parameterized;

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

        bytes[mem::size_of::<sgx_quote3_t>()..].fill(0);

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
    fn quote_with_authentication_data() {
        let mut binding = [4u8; MIN_QUOTE_SIZE + 1];
        let bytes = quotify_bytes(binding.as_mut_slice());
        bytes[AUTH_DATA_OFFSET] = 1;
        let quote = Quote3::try_from(bytes.as_ref()).unwrap();
        assert_eq!(quote.raw_bytes, bytes);
    }

    #[test]
    fn quote_too_small_for_authentication_data() {
        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        bytes[AUTH_DATA_OFFSET] = 1;
        assert_eq!(
            Quote3::try_from(bytes.as_ref()),
            Err(Error::InputLength {
                required: MIN_QUOTE_SIZE + 1,
                actual: MIN_QUOTE_SIZE
            })
        );
    }

    #[test]
    fn quote_with_certification_data() {
        let mut binding = [4u8; MIN_QUOTE_SIZE + 1];
        let bytes = quotify_bytes(binding.as_mut_slice());
        // 2 (auth data size) + 2 (cert data type )
        bytes[QUOTE_SIZE + 2 + 2] = 1;
        let quote = Quote3::try_from(bytes.as_ref()).unwrap();
        assert_eq!(quote.raw_bytes, bytes);
    }

    #[test]
    fn quote_too_small_for_certification_data() {
        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        // 2 (auth data size) + 2 (cert data type )
        bytes[QUOTE_SIZE + 2 + 2] = 1;
        assert_eq!(
            Quote3::try_from(bytes.as_ref()),
            Err(Error::InputLength {
                required: MIN_QUOTE_SIZE + 1,
                actual: MIN_QUOTE_SIZE
            })
        );
    }

    #[test]
    fn quote_with_auth_and_cert_data() {
        // 2 (cert data type ) + 4 (cert data size)
        const CERT_FIELD_CONSTANT_SIZE: usize = 6;

        // The authentication data wll be so large that it exceeds
        // `MIN_QUOTE_SIZE`, thus pushing the certification data fully outside
        // of the `MIN_QUOTE_SIZE`
        let mut binding = [5u8; MIN_QUOTE_SIZE + CERT_FIELD_CONSTANT_SIZE + 1];
        let bytes = quotify_bytes(binding.as_mut_slice());

        bytes[AUTH_DATA_OFFSET] = CERT_FIELD_CONSTANT_SIZE as u8;

        // 2 (cert data type )
        bytes[MIN_QUOTE_SIZE + 2] = 1;

        let quote = Quote3::try_from(bytes.as_ref()).unwrap();
        assert_eq!(quote.raw_bytes, bytes);
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
}
