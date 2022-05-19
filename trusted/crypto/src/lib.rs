// Copyright (c) 2022 The MobileCoin Foundation
//! Rust wrappers for the SGX SDK trusted crypto library (tcrypto).

use mc_sgx_crypto_sys::{sgx_sha256_hash_t, sgx_sha256_msg, sgx_status_t};
use std::{convert::TryInto, num::TryFromIntError};

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

pub struct Sha256Hash {
    hash: [u8; Sha256Hash::SIZE],
}

impl Sha256Hash {
    pub const SIZE: usize = 32;
    pub fn as_slice(&self) -> &[u8] {
        &self.hash
    }
}

pub fn sha256_message(data: &[u8]) -> Result<Sha256Hash, Error> {
    let mut hash: sgx_sha256_hash_t = Default::default();
    let result = unsafe { sgx_sha256_msg(data.as_ptr(), data.len().try_into()?, &mut hash) };
    match result {
        sgx_status_t::SGX_SUCCESS => Ok(Sha256Hash { hash }),
        x => Err(Error::SGX(x)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn run_sha256_804() {
        let bytes: [u8; 3] = [8, 0, 4];
        let hash = sha256_message(&bytes).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let expected = hasher.finalize();
        assert_eq!(hash.as_slice(), &expected[..]);
    }

    #[test]
    fn run_sha256_7420() {
        let bytes: [u8; 4] = [7, 4, 2, 0];
        let hash = sha256_message(&bytes).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let expected = hasher.finalize();
        assert_eq!(hash.as_slice(), &expected[..]);
    }
}
