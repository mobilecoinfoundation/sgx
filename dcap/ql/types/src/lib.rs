// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]

use mc_sgx_core_types::FfiError;
use mc_sgx_dcap_ql_sys_types::sgx_ql_path_type_t;

/// Paths (location and filename) to be override the default entries.
#[non_exhaustive]
#[derive(Eq, PartialEq, Debug)]
pub enum Path {
    /// Quoting Enclave (QE3)
    QuotingEnclave,
    /// Provisioning Certificate Enclave (PCE)
    ProvisioningCertificateEnclave,
    /// Quote Provider library (QPL)
    QuoteProviderLibrary,
    /// Id Enclave (IDE)
    IdEnclave,
}

impl TryFrom<sgx_ql_path_type_t> for Path {
    type Error = FfiError;

    fn try_from(p: sgx_ql_path_type_t) -> Result<Self, Self::Error> {
        match p {
            sgx_ql_path_type_t::SGX_QL_QE3_PATH => Ok(Self::QuotingEnclave),
            sgx_ql_path_type_t::SGX_QL_PCE_PATH => Ok(Self::ProvisioningCertificateEnclave),
            sgx_ql_path_type_t::SGX_QL_QPL_PATH => Ok(Self::QuoteProviderLibrary),
            sgx_ql_path_type_t::SGX_QL_IDE_PATH => Ok(Self::IdEnclave),
            p => Err(FfiError::UnknownEnumValue(p.0.into())),
        }
    }
}

impl From<Path> for sgx_ql_path_type_t {
    fn from(p: Path) -> sgx_ql_path_type_t {
        match p {
            Path::QuotingEnclave => sgx_ql_path_type_t::SGX_QL_QE3_PATH,
            Path::ProvisioningCertificateEnclave => sgx_ql_path_type_t::SGX_QL_PCE_PATH,
            Path::QuoteProviderLibrary => sgx_ql_path_type_t::SGX_QL_QPL_PATH,
            Path::IdEnclave => sgx_ql_path_type_t::SGX_QL_IDE_PATH,
        }
    }
}

#[cfg(test)]
mod test {
    use yare::parameterized;
    extern crate std;
    use super::*;

    #[parameterized(
    qe3 = { sgx_ql_path_type_t::SGX_QL_QE3_PATH, Path::QuotingEnclave },
    pce = { sgx_ql_path_type_t::SGX_QL_PCE_PATH, Path::ProvisioningCertificateEnclave },
    qpl = { sgx_ql_path_type_t::SGX_QL_QPL_PATH, Path::QuoteProviderLibrary },
    ide = { sgx_ql_path_type_t::SGX_QL_IDE_PATH, Path::IdEnclave },
    )]
    fn from_sgx_to_path(sgx_path: sgx_ql_path_type_t, expected: Path) {
        let path: Path = sgx_path.try_into().unwrap();
        assert_eq!(path, expected);
    }

    #[parameterized(
    qe3 = { Path::QuotingEnclave, sgx_ql_path_type_t::SGX_QL_QE3_PATH },
    pce = { Path::ProvisioningCertificateEnclave, sgx_ql_path_type_t::SGX_QL_PCE_PATH },
    qpl = { Path::QuoteProviderLibrary, sgx_ql_path_type_t::SGX_QL_QPL_PATH },
    ide = { Path::IdEnclave, sgx_ql_path_type_t::SGX_QL_IDE_PATH },
    )]
    fn from_path_to_sgx(path: Path, expected: sgx_ql_path_type_t) {
        let sgx_path: sgx_ql_path_type_t = path.into();
        assert_eq!(sgx_path, expected);
    }
    #[test]
    fn sgx_path_out_of_bounds_panics() {
        let result = Path::try_from(sgx_ql_path_type_t(4));
        assert!(result.is_err());
    }
}
