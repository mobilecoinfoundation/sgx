// Copyright (c) 2022 The MobileCoin Foundation

// ! This module provides types related to request policy

use mc_sgx_core_types::FfiError;
use mc_sgx_dcap_sys_types::sgx_ql_request_policy_t;

/// Policy used for loading enclaves
#[non_exhaustive]
#[derive(Default, Eq, PartialEq, Debug)]
pub enum RequestPolicy {
    /// Quoting Enclave is initialized on first use and reused until process
    /// ends
    #[default] // Per sgx_pce.h
    Persistent,
    /// Quoting Enclave is initialized and terminated on every quote.  if a
    /// previous quoting enclave exists, it is stopped and restarted before
    /// quoting.
    Ephemeral,
}

impl TryFrom<sgx_ql_request_policy_t> for RequestPolicy {
    type Error = FfiError;

    fn try_from(p: sgx_ql_request_policy_t) -> Result<Self, Self::Error> {
        match p {
            sgx_ql_request_policy_t::SGX_QL_PERSISTENT => Ok(Self::Persistent),
            sgx_ql_request_policy_t::SGX_QL_EPHEMERAL => Ok(Self::Ephemeral),
            p => Err(FfiError::UnknownEnumValue(p.0.into())),
        }
    }
}

impl From<RequestPolicy> for sgx_ql_request_policy_t {
    fn from(p: RequestPolicy) -> sgx_ql_request_policy_t {
        match p {
            RequestPolicy::Persistent => sgx_ql_request_policy_t::SGX_QL_PERSISTENT,
            RequestPolicy::Ephemeral => sgx_ql_request_policy_t::SGX_QL_EPHEMERAL,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use yare::parameterized;

    #[parameterized(
    persistent = { sgx_ql_request_policy_t::SGX_QL_PERSISTENT, RequestPolicy::Persistent },
    ephemeral = { sgx_ql_request_policy_t::SGX_QL_EPHEMERAL, RequestPolicy::Ephemeral },
    defualt = { sgx_ql_request_policy_t::SGX_QL_DEFAULT, RequestPolicy::Persistent },
    )]
    fn from_sgx_to_policy(sgx_policy: sgx_ql_request_policy_t, expected: RequestPolicy) {
        let policy: RequestPolicy = sgx_policy.try_into().unwrap();
        assert_eq!(policy, expected);
    }

    #[parameterized(
    persistent = { RequestPolicy::Persistent, sgx_ql_request_policy_t::SGX_QL_PERSISTENT },
    ephemeral = { RequestPolicy::Ephemeral, sgx_ql_request_policy_t::SGX_QL_EPHEMERAL },
    )]
    fn from_policy_to_sgx(policy: RequestPolicy, expected: sgx_ql_request_policy_t) {
        let sgx_policy: sgx_ql_request_policy_t = policy.into();
        assert_eq!(sgx_policy, expected);
    }
    #[test]
    fn sgx_policy_out_of_bounds_panics() {
        let result = RequestPolicy::try_from(sgx_ql_request_policy_t(2));
        assert!(result.is_err());
    }
}
