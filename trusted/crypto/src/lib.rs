// Copyright (c) 2022 The MobileCoin Foundation
//! Rust wrappers for the SGX SDK trusted crypto library (tcrypto).

use mc_sgx_crypto_sys::{
    sgx_sha256_close, sgx_sha256_get_hash, sgx_sha256_hash_t, sgx_sha256_init, sgx_sha256_msg,
    sgx_sha256_update, sgx_sha_state_handle_t, sgx_status_t,
};
use std::{convert::TryInto, num::TryFromIntError, ptr};

#[derive(Debug)]
pub enum Error {
    SGX(sgx_status_t),
    ConversionError,
}

impl From<TryFromIntError> for Error {
    fn from(_: TryFromIntError) -> Self {
        Error::ConversionError
    }
}

/// A SHA256 hash over some data.  See [Sha256::hash()] and [Sha256Builder]
pub struct Sha256 {
    hash: [u8; Sha256::SIZE],
}

impl Sha256 {
    const SIZE: usize = 32;

    /// The hash value as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.hash
    }

    /// Compute the hash of `data`.
    ///
    /// # Arguments
    /// - `data` The data to compute the hash for.
    ///
    /// # Returns
    /// The [Sha256] hash of the `data`.  Use [Sha256::as_slice()] to access
    /// the bytes of the hash
    ///
    /// # Errors
    ///
    /// If this function will return an error when:
    /// - there is not enough memory in SGX
    /// - there is an internal library error in SGX
    pub fn hash(data: &[u8]) -> Result<Sha256, Error> {
        let mut hash: sgx_sha256_hash_t = Default::default();
        let result = unsafe { sgx_sha256_msg(data.as_ptr(), data.len().try_into()?, &mut hash) };
        match result {
            sgx_status_t::SGX_SUCCESS => Ok(Sha256 { hash }),
            x => Err(Error::SGX(x)),
        }
    }
}

/// Builds a [Sha256] hash in a piecewise fashion.  This can be used when all
/// of the data to hash is not available in contiguous memory.
pub struct Sha256Builder {
    handle: sgx_sha_state_handle_t,
}

impl Sha256Builder {
    /// Create a new builder
    ///
    /// # Returns
    /// An empty [Sha256Builder] ready to compute a hash.
    /// See [Sha256Builder::update()].
    ///
    /// # Errors
    ///
    /// If this function will return an error when:
    /// - there is not enough memory in SGX
    /// - there is an internal library error in SGX
    pub fn new() -> Result<Self, Error> {
        let mut handle: sgx_sha_state_handle_t = ptr::null_mut();
        let result = unsafe { sgx_sha256_init(&mut handle) };
        match result {
            sgx_status_t::SGX_SUCCESS => Ok(Sha256Builder { handle }),
            x => Err(Error::SGX(x)),
        }
    }

    /// Update the data hashed so far
    ///
    /// # Arguments
    /// - `data` The data to use in updating the hash.
    ///
    /// # Returns
    /// The updated [Sha256Builder].
    ///
    /// # Errors
    ///
    /// This function will return an error if there is an internal library error
    /// in SGX.
    pub fn update(self, data: &[u8]) -> Result<Self, Error> {
        let result =
            unsafe { sgx_sha256_update(data.as_ptr(), data.len().try_into()?, self.handle) };
        match result {
            sgx_status_t::SGX_SUCCESS => Ok(self),
            x => Err(Error::SGX(x)),
        }
    }

    /// Get the final hash of all the data seen in [Sha256Builder::update()]
    ///
    /// # Returns
    /// The [Sha256] hash of all the `data`, in order, provided in
    /// [Sha256Builder::update()]
    ///
    /// # Errors
    ///
    /// This function will return an error if there is an internal library error
    /// in SGX.
    pub fn build(self) -> Result<Sha256, Error> {
        let mut hash: sgx_sha256_hash_t = Default::default();
        let result = unsafe { sgx_sha256_get_hash(self.handle, &mut hash) };
        // The errors from sgx_sha256_close() are success or a NULL pointer.
        // There isn't much error handling we can do if for some reason
        // self.handle is a NULL pointer.
        unsafe { sgx_sha256_close(self.handle) };
        match result {
            sgx_status_t::SGX_SUCCESS => Ok(Sha256 { hash }),
            x => Err(Error::SGX(x)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{self, Digest};

    #[test]
    fn run_sha256_804() {
        let bytes: [u8; 3] = [8, 0, 4];
        let hash = Sha256::hash(&bytes).unwrap();
        let expected = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&bytes);
            hasher.finalize()
        };
        assert_eq!(hash.as_slice(), &expected[..]);
    }

    #[test]
    fn run_sha256_7420() {
        let bytes: [u8; 4] = [7, 4, 2, 0];
        let hash = Sha256::hash(&bytes).unwrap();
        let expected = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&bytes);
            hasher.finalize()
        };
        assert_eq!(hash.as_slice(), &expected[..]);
    }

    #[test]
    fn build_sha256_1984() {
        let bytes: [u8; 4] = [1, 9, 8, 4];
        let mut builder = Sha256Builder::new().unwrap();
        for i in bytes {
            builder = builder.update(&[i]).unwrap();
        }
        let hash = builder.build().unwrap();
        let expected = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&bytes);
            hasher.finalize()
        };
        assert_eq!(hash.as_slice(), &expected[..]);
    }

    #[test]
    fn build_sha256_1066() {
        let bytes: [u8; 4] = [1, 9, 6, 6];
        let mut builder = Sha256Builder::new().unwrap();
        builder = builder.update(&bytes).unwrap();
        let hash = builder.build().unwrap();
        let expected = {
            let mut hasher = sha2::Sha256::new();
            hasher.update(&bytes);
            hasher.finalize()
        };
        assert_eq!(hash.as_slice(), &expected[..]);
    }
}
