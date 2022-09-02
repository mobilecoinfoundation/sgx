// Copyright (c) 2018-2022 The MobileCoin Foundation

//! This module contains the wrapper types for an sgx_measurement_t
//!
//! Different types are used for MrSigner and MrEnclave to prevent misuse.

use crate::impl_newtype_for_bytestruct;
use mc_sgx_core_sys_types::{sgx_measurement_t, SGX_HASH_SIZE};

/// An opaque type for MRENCLAVE values
///
/// A MRENCLAVE value is a chained cryptographic hash of the signed
/// enclave binary (.so), and the results of the page initialization
/// steps which created the enclave's pages.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct MrEnclave(sgx_measurement_t);

/// An opaque type for MRSIGNER values.
///
/// A MRSIGNER value is a cryptographic hash of the public key an enclave
/// was signed with.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct MrSigner(sgx_measurement_t);

impl_newtype_for_bytestruct! {
    MrEnclave, sgx_measurement_t, SGX_HASH_SIZE, m;
    MrSigner, sgx_measurement_t, SGX_HASH_SIZE, m;
}

/// An enumeration of measurement options, mainly useful for describing
/// enclave-vs-author attestation policy.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Measurement {
    MrEnclave(MrEnclave),
    MrSigner(MrSigner),
}

impl From<MrEnclave> for Measurement {
    fn from(mr_enclave: MrEnclave) -> Self {
        Measurement::MrEnclave(mr_enclave)
    }
}

impl From<MrSigner> for Measurement {
    fn from(mr_signer: MrSigner) -> Self {
        Measurement::MrSigner(mr_signer)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn from_mr_enclave() {
        let mr_enclave = MrEnclave::from([5u8; MrEnclave::SIZE]);
        let measurement: Measurement = mr_enclave.into();
        assert_eq!(measurement, Measurement::MrEnclave(mr_enclave));
    }

    #[test]
    fn from_mr_signer() {
        let mr_signer = MrSigner::from([8u8; MrSigner::SIZE]);
        let measurement: Measurement = mr_signer.into();
        assert_eq!(measurement, Measurement::MrSigner(mr_signer));
    }
}
