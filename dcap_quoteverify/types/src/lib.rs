// Copyright (c) 2022 The MobileCoin Foundation

//! Rust wrappers for SGX DCAP quoteverify types

#![no_std]

extern crate alloc;

use mc_sgx_core_types::FfiError;
use mc_sgx_dcap_quoteverify_sys_types::sgx_qv_path_type_t;

#[non_exhaustive]
#[derive(Eq, PartialEq, Debug)]
pub enum Path {
    QuoteVerificationEnclave,
    QuoteProviderLibrary,
}

impl TryFrom<sgx_qv_path_type_t> for Path {
    type Error = FfiError;

    fn try_from(p: sgx_qv_path_type_t) -> Result<Self, Self::Error> {
        match p {
            sgx_qv_path_type_t::SGX_QV_QVE_PATH => Ok(Self::QuoteVerificationEnclave),
            sgx_qv_path_type_t::SGX_QV_QPL_PATH => Ok(Self::QuoteProviderLibrary),
            p => Err(FfiError::UnknownEnumValue(p.0.into())),
        }
    }
}

impl From<Path> for sgx_qv_path_type_t {
    fn from(p: Path) -> sgx_qv_path_type_t {
        match p {
            Path::QuoteVerificationEnclave => sgx_qv_path_type_t::SGX_QV_QVE_PATH,
            Path::QuoteProviderLibrary => sgx_qv_path_type_t::SGX_QV_QPL_PATH,
        }
    }
}

#[cfg(test)]
mod test {
    use yare::{ide, parameterized};
    extern crate std;
    use super::*;

    ide!();

    #[parameterized(
        qve = { sgx_qv_path_type_t::SGX_QV_QVE_PATH, Path::QuoteVerificationEnclave },
        qpl = { sgx_qv_path_type_t::SGX_QV_QPL_PATH, Path::QuoteProviderLibrary },
    )]
    fn from_sgx_to_path(sgx_path: sgx_qv_path_type_t, expected: Path) {
        let path: Path = sgx_path.try_into().unwrap();
        assert_eq!(path, expected);
    }

    #[parameterized(
    qve = { Path::QuoteVerificationEnclave, sgx_qv_path_type_t::SGX_QV_QVE_PATH },
    qpl = { Path::QuoteProviderLibrary, sgx_qv_path_type_t::SGX_QV_QPL_PATH },
    )]
    fn from_path_to_sgx(path: Path, expected: sgx_qv_path_type_t) {
        let sgx_path: sgx_qv_path_type_t = path.into();
        assert_eq!(sgx_path, expected);
    }
    #[test]
    fn sgx_path_out_of_bounds_panics() {
        let result = Path::try_from(sgx_qv_path_type_t(2));
        assert!(result.is_err());
    }
}
