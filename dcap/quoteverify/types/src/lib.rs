// Copyright (c) 2022-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]

use constant_time_derive::ConstantTimeEq;
use mc_sgx_core_types::FfiError;
use mc_sgx_dcap_quoteverify_sys_types::sgx_qv_path_type_t;

#[non_exhaustive]
#[derive(Eq, PartialEq, Debug, ConstantTimeEq)]
pub enum PathKind {
    QuoteVerificationEnclave,
    QuoteProviderLibrary,
}

impl TryFrom<sgx_qv_path_type_t> for PathKind {
    type Error = FfiError;

    fn try_from(p: sgx_qv_path_type_t) -> Result<Self, Self::Error> {
        match p {
            sgx_qv_path_type_t::SGX_QV_QVE_PATH => Ok(Self::QuoteVerificationEnclave),
            sgx_qv_path_type_t::SGX_QV_QPL_PATH => Ok(Self::QuoteProviderLibrary),
            p => Err(FfiError::UnknownEnumValue(p.0.into())),
        }
    }
}

impl From<PathKind> for sgx_qv_path_type_t {
    fn from(p: PathKind) -> sgx_qv_path_type_t {
        match p {
            PathKind::QuoteVerificationEnclave => sgx_qv_path_type_t::SGX_QV_QVE_PATH,
            PathKind::QuoteProviderLibrary => sgx_qv_path_type_t::SGX_QV_QPL_PATH,
        }
    }
}

#[cfg(test)]
mod test {
    use subtle::ConstantTimeEq;
    use yare::parameterized;
    extern crate std;
    use super::*;

    #[parameterized(
        qve = { sgx_qv_path_type_t::SGX_QV_QVE_PATH, PathKind::QuoteVerificationEnclave },
        qpl = { sgx_qv_path_type_t::SGX_QV_QPL_PATH, PathKind::QuoteProviderLibrary },
    )]
    fn from_sgx_to_path(sgx_path: sgx_qv_path_type_t, expected: PathKind) {
        let path: PathKind = sgx_path.try_into().unwrap();
        assert_eq!(path, expected);
    }

    #[parameterized(
    qve = { PathKind::QuoteVerificationEnclave, sgx_qv_path_type_t::SGX_QV_QVE_PATH },
    qpl = { PathKind::QuoteProviderLibrary, sgx_qv_path_type_t::SGX_QV_QPL_PATH },
    )]
    fn from_path_to_sgx(path: PathKind, expected: sgx_qv_path_type_t) {
        let sgx_path: sgx_qv_path_type_t = path.into();
        assert_eq!(sgx_path, expected);
    }
    #[test]
    fn sgx_path_out_of_bounds_panics() {
        let result = PathKind::try_from(sgx_qv_path_type_t(2));
        assert!(result.is_err());
    }

    #[test]
    fn ct_eq_path_kind() {
        let first = PathKind::try_from(sgx_qv_path_type_t(1));
        let second = PathKind::try_from(sgx_qv_path_type_t(1));

        let choice_result = first.unwrap().ct_eq(&second.unwrap());
        let result: bool = From::from(choice_result);

        assert!(result);
    }
}
