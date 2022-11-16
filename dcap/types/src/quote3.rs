// Copyright (c) 2022 The MobileCoin Foundation

//! This module provides types related to Quote v3

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::mem;
use mc_sgx_core_types::{QuoteNonce, ReportData};
use mc_sgx_dcap_sys_types::{sgx_ql_ecdsa_sig_data_t, sgx_quote3_t};
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

/// The minimum size of a byte array to contain a [`Quote3`]
///
// 8 is from the 2 bytes for QE authentication data size and 2(type) + 4(size)
// for QE certification data
pub const MIN_QUOTE_SIZE: usize = QUOTE_SIZE + 8;

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

type Result<T> = ::core::result::Result<T, Error>;

/// Quote version 3
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Quote3<T> {
    bytes: T,
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
        hasher.update(&self.bytes);
        let hash = hasher.finalize();

        let mut data = [0u8; ReportData::SIZE];
        data[..hash.len()].copy_from_slice(hash.as_slice());

        data.ct_eq(report_data.as_ref()).into()
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
        let ref_bytes = bytes.as_ref();
        let bytes_length = ref_bytes.len();
        if bytes_length < MIN_QUOTE_SIZE {
            return Err(Error::InputLength {
                required: MIN_QUOTE_SIZE,
                actual: bytes_length,
            });
        }

        // This shouldn't fail since we checked for `MIN_QUOTE_SIZE` above.
        let version = u16_from_bytes(ref_bytes)?;
        if version != 3 {
            return Err(Error::Version(version));
        }

        let auth_data = AuthenticationData::try_from(&bytes.as_ref()[AUTH_DATA_OFFSET..])
            .map_err(|e| e.increase_size(QUOTE_SIZE))?;

        let quote_with_auth_size = QUOTE_SIZE + auth_data.size();

        let _ = CertificationData::try_from(&bytes.as_ref()[quote_with_auth_size..])
            .map_err(|e| e.increase_size(quote_with_auth_size))?;

        Ok(Self { bytes })
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
    bytes: &'a [u8],
    // Since this has to be read always we unpack for availability.
    // This is the `size` field, *not* the length of `bytes`.
    data_size: usize,
}

impl<'a> TryFrom<&'a [u8]> for AuthenticationData<'a> {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let actual = bytes.len();

        let data_size = u16_from_bytes(bytes)? as usize;

        let required = data_size + mem::size_of::<u16>();
        if actual < required {
            Err(Error::InputLength { required, actual })
        } else {
            Ok(Self { bytes, data_size })
        }
    }
}

impl<'a> AuthenticationData<'a> {
    pub fn size(&self) -> usize {
        self.data_size + mem::size_of::<u16>()
    }
}

/// The Quoting enclave certification data
///
/// Table 9 of
/// <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct CertificationData<'a> {
    bytes: &'a [u8],
    // Since these are small and the `size` has to be read we always unpack
    // for availability.
    data_type: u16,
    // This is the size of the data field, *not* the size of `bytes`
    data_size: usize,
}

impl<'a> TryFrom<&'a [u8]> for CertificationData<'a> {
    type Error = Error;
    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let actual = bytes.len();

        // type (2 bytes) + size (4 bytes)
        let mut required = mem::size_of::<u16>() + mem::size_of::<u32>();

        if actual < required {
            return Err(Error::InputLength { required, actual });
        }

        // These shouldn't fail since we ensured the length up above
        let data_type = u16_from_bytes(bytes)?;
        let data_size = u32_from_bytes(&bytes[mem::size_of::<u16>()..])? as usize;

        required += data_size;
        if actual < required {
            Err(Error::InputLength { required, actual })
        } else {
            Ok(Self {
                bytes,
                data_type,
                data_size,
            })
        }
    }
}

fn u32_from_bytes(bytes: &[u8]) -> Result<u32> {
    const SIZE: usize = mem::size_of::<u32>();
    let value_bytes = bytes.get(..SIZE).ok_or(Error::InputLength {
        required: SIZE,
        actual: bytes.len(),
    })?;
    let mut copy_bytes = [0u8; SIZE];
    copy_bytes.copy_from_slice(value_bytes);
    Ok(u32::from_le_bytes(copy_bytes))
}

fn u16_from_bytes(bytes: &[u8]) -> Result<u16> {
    const SIZE: usize = mem::size_of::<u16>();
    let value_bytes = bytes.get(..SIZE).ok_or(Error::InputLength {
        required: SIZE,
        actual: bytes.len(),
    })?;
    let mut copy_bytes = [0u8; SIZE];
    copy_bytes.copy_from_slice(value_bytes);
    Ok(u16::from_le_bytes(copy_bytes))
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
        hasher.update(quote.bytes);
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

        for byte in &mut bytes[AUTH_DATA_OFFSET..] {
            *byte = 0;
        }
        bytes
    }

    #[test]
    fn quote_from_slice() {
        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        let quote = Quote3::try_from(bytes.as_ref()).unwrap();
        assert_eq!(quote.bytes, bytes);
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
        assert_eq!(quote.bytes, bytes);
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
        assert_eq!(quote.bytes, bytes);
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
        assert_eq!(quote.bytes, bytes);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn quote_from_vec() {
        let mut binding = [4u8; MIN_QUOTE_SIZE];
        let bytes = quotify_bytes(binding.as_mut_slice());
        let quote: Quote3<Vec<u8>> = bytes.to_vec().try_into().unwrap();
        assert_eq!(quote.bytes, bytes);
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
}
