// Copyright (c) 2022 The MobileCoin Foundation

//! This module provides types related to Quote v3

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use mc_sgx_core_types::{QuoteNonce, ReportData};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

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
}

impl<'a> From<&'a [u8]> for Quote3<&'a [u8]> {
    fn from(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

#[cfg(feature = "alloc")]
impl From<Vec<u8>> for Quote3<Vec<u8>> {
    fn from(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    #[cfg(feature = "alloc")]
    use std::vec;

    use super::*;

    /// Provides ReportData for a given quote and nonce.
    ///
    /// This is meant to mimic the `sgx_report_data_t` in the QE report that
    /// comes back in the `report_info` of `sgx_ql_get_quote()`
    fn report_data_from_quote_and_nonce(quote: &Quote3<&[u8]>, nonce: &QuoteNonce) -> ReportData {
        let mut report_data = [0u8; ReportData::SIZE];
        let mut hasher = Sha256::new();
        hasher.update(nonce);
        hasher.update(quote.bytes);
        let hash = hasher.finalize();
        report_data[..hash.len()].copy_from_slice(hash.as_slice());
        report_data.into()
    }

    #[test]
    fn quote_from_slice() {
        let bytes = [4u8; 6].as_slice();
        let quote: Quote3<&[u8]> = bytes.into();
        assert_eq!(quote.bytes, bytes);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn quote_from_vec() {
        let bytes = vec![4u8; 6];
        let quote: Quote3<Vec<u8>> = bytes.clone().into();
        assert_eq!(quote.bytes, bytes);
    }

    #[test]
    fn valid_quote_nonce_1_succeeds() {
        let bytes = [3u8; 20].as_slice();
        let quote: Quote3<&[u8]> = bytes.into();
        let nonce = [1u8; QuoteNonce::SIZE].into();
        let report_data = report_data_from_quote_and_nonce(&quote, &nonce);
        assert_eq!(quote.verify_nonce(&nonce, &report_data), true);
    }

    #[test]
    fn valid_quote_nonce_5_succeeds() {
        let bytes = [8u8; 60].as_slice();
        let quote: Quote3<&[u8]> = bytes.into();
        let nonce = [5u8; QuoteNonce::SIZE].into();
        let report_data = report_data_from_quote_and_nonce(&quote, &nonce);
        assert_eq!(quote.verify_nonce(&nonce, &report_data), true);
    }

    #[test]
    fn quote_nonce_off_by_one_fails() {
        let bytes = [8u8; 60].as_slice();
        let quote: Quote3<&[u8]> = bytes.into();
        let mut nonce = [5u8; QuoteNonce::SIZE].into();
        let report_data = report_data_from_quote_and_nonce(&quote, &nonce);

        let contents: &mut [u8] = nonce.as_mut();
        contents[0] += 1;

        assert_eq!(quote.verify_nonce(&nonce, &report_data), false);
    }

    #[test]
    fn trailing_report_data_non_zero_fails() {
        let bytes = [8u8; 60].as_slice();
        let quote: Quote3<&[u8]> = bytes.into();
        let nonce = [5u8; QuoteNonce::SIZE].into();
        let mut report_data = report_data_from_quote_and_nonce(&quote, &nonce);

        let contents: &mut [u8] = report_data.as_mut();
        let hash_size = 32;
        contents[hash_size] += 1;

        assert_eq!(quote.verify_nonce(&nonce, &report_data), false);
    }
}
