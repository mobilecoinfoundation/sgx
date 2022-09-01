// Copyright (c) 2022 The MobileCoin Foundation

use mc_sgx_core_types::{
    impl_newtype_for_bytestruct, new_type_accessors_impls, Attributes, CpuSvn, FfiError,
    IsvProductId, IsvSvn, Measurement, MiscellaneousSelect,
};
use mc_sgx_tservice_sys_types::{
    sgx_dh_session_enclave_identity_t, sgx_dh_session_role_t, sgx_dh_session_t,
    SGX_DH_SESSION_DATA_SIZE,
};

/// A session used in Diffie Hellman (DH) secure session establishment
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct Session(sgx_dh_session_t);

impl_newtype_for_bytestruct! {
   Session, sgx_dh_session_t, SGX_DH_SESSION_DATA_SIZE, sgx_dh_session;
}

/// Session enclave identity
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct EnclaveId(sgx_dh_session_enclave_identity_t);

impl EnclaveId {
    /// CPU security version number
    pub fn cpu_svn(&self) -> CpuSvn {
        self.0.cpu_svn.into()
    }

    /// Miscellaneous select bits of the enclave
    pub fn miscellaneous_select(&self) -> MiscellaneousSelect {
        self.0.misc_select.into()
    }

    /// Attributes
    pub fn attributes(&self) -> Attributes {
        self.0.attributes.into()
    }

    /// The MRENCLAVE measurement
    pub fn mr_enclave(&self) -> Measurement {
        Measurement::MrEnclave(self.0.mr_enclave.into())
    }

    /// The MRSIGNER measurement
    pub fn mr_signer(&self) -> Measurement {
        Measurement::MrSigner(self.0.mr_signer.into())
    }

    /// The ISV product ID
    pub fn isv_product_id(&self) -> IsvProductId {
        self.0.isv_prod_id.into()
    }

    /// The ISV SVN
    pub fn isv_svn(&self) -> IsvSvn {
        self.0.isv_svn.into()
    }
}

new_type_accessors_impls! {
   EnclaveId, sgx_dh_session_enclave_identity_t;
}

/// Session Role
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[non_exhaustive]
#[repr(u32)]
pub enum Role {
    /// The initiator of a Diffie Hellman session
    #[default]
    Initiator,

    /// The responder of a Diffie Hellman session
    Responder,
}

impl TryFrom<sgx_dh_session_role_t> for Role {
    type Error = FfiError;
    fn try_from(role: sgx_dh_session_role_t) -> Result<Role, FfiError> {
        match role {
            sgx_dh_session_role_t::SGX_DH_SESSION_INITIATOR => Ok(Role::Initiator),
            sgx_dh_session_role_t::SGX_DH_SESSION_RESPONDER => Ok(Role::Responder),
            sgx_dh_session_role_t(v) => Err(FfiError::UnknownEnumValue(v.into())),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_core_sys_types::{
        sgx_attributes_t, sgx_cpu_svn_t, sgx_measurement_t, SGX_CPUSVN_SIZE, SGX_HASH_SIZE,
    };
    use mc_sgx_core_types::{MrEnclave, MrSigner};
    use yare::parameterized;

    #[parameterized(
   initiator = {0, Ok(Role::Initiator)},
   reposonder = {1, Ok(Role::Responder)},
   out_of_bounds = {2, Err(FfiError::UnknownEnumValue(2))},
   )]
    fn try_from_session_role(raw_value: u32, result: Result<Role, FfiError>) {
        assert_eq!(Role::try_from(sgx_dh_session_role_t(raw_value)), result);
    }

    #[test]
    fn enclave_id_from_sgx_id() {
        let sgx_id = sgx_dh_session_enclave_identity_t {
            cpu_svn: sgx_cpu_svn_t {
                svn: [1u8; SGX_CPUSVN_SIZE],
            },
            misc_select: 2,
            reserved_1: [3u8; 28],
            attributes: sgx_attributes_t { flags: 4, xfrm: 5 },
            mr_enclave: sgx_measurement_t {
                m: [6u8; SGX_HASH_SIZE],
            },
            reserved_2: [7u8; 32],
            mr_signer: sgx_measurement_t {
                m: [8u8; SGX_HASH_SIZE],
            },
            reserved_3: [9u8; 96],
            isv_prod_id: 10,
            isv_svn: 11,
        };
        let enclave_id = EnclaveId::from(sgx_id);
        assert_eq!(enclave_id.cpu_svn(), CpuSvn::from([1u8; CpuSvn::SIZE]));
        assert_eq!(
            enclave_id.miscellaneous_select(),
            MiscellaneousSelect::from(2)
        );
        assert_eq!(
            enclave_id.attributes(),
            Attributes::default()
                .set_flags(4)
                .set_extended_features_mask(5)
        );
        assert_eq!(
            enclave_id.mr_enclave(),
            Measurement::MrEnclave(MrEnclave::from([6u8; SGX_HASH_SIZE]))
        );
        assert_eq!(
            enclave_id.mr_signer(),
            Measurement::MrSigner(MrSigner::from([8u8; SGX_HASH_SIZE]))
        );
        assert_eq!(enclave_id.isv_product_id(), IsvProductId::from(10));
        assert_eq!(enclave_id.isv_svn(), IsvSvn::from(11));
    }
}
