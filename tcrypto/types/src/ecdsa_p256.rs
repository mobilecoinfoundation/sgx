// Copyright (c) 2022 The MobileCoin Foundation
//! Elliptic curve digital signature algorithm (ECDSA) types for curve P-256

use mc_sgx_core_types::new_type_accessors_impls;
use mc_sgx_tcrypto_sys_types::{sgx_ec256_public_t, SGX_ECP256_KEY_SIZE};

/// Elliptic curve digital signature algorithm (ECDSA) curve P-256 public key
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct PublicKey(sgx_ec256_public_t);

impl PublicKey {
    /// The x coordinate of the public key
    pub fn x(&self) -> KeyCoordinate {
        self.0.gx.into()
    }

    /// The y coordinate of the public key
    pub fn y(&self) -> KeyCoordinate {
        self.0.gy.into()
    }
}

new_type_accessors_impls! {
   PublicKey, sgx_ec256_public_t;
}

/// A coordinate of a key.  I.e. the X or Y or in the case of a private key it's
/// the private key.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct KeyCoordinate([u8; SGX_ECP256_KEY_SIZE]);

impl From<[u8; SGX_ECP256_KEY_SIZE]> for KeyCoordinate {
    fn from(bytes: [u8; SGX_ECP256_KEY_SIZE]) -> Self {
        Self(bytes)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn public_from_sgx() {
        let sgx_key = sgx_ec256_public_t {
            gx: [1u8; SGX_ECP256_KEY_SIZE],
            gy: [2u8; SGX_ECP256_KEY_SIZE],
        };

        let public = PublicKey::from(sgx_key);
        assert_eq!(public.x(), KeyCoordinate::from([1u8; SGX_ECP256_KEY_SIZE]));
        assert_eq!(public.y(), KeyCoordinate::from([2u8; SGX_ECP256_KEY_SIZE]));
    }
}
