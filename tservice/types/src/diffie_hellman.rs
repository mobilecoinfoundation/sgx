// Copyright (c) 2022 The MobileCoin Foundation

use mc_sgx_core_types::impl_newtype_for_bytestruct;
use mc_sgx_tservice_sys_types::{sgx_dh_session_t, SGX_DH_SESSION_DATA_SIZE};

#[derive(Debug, Default, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
pub struct Session(sgx_dh_session_t);

impl_newtype_for_bytestruct! {
   Session, sgx_dh_session_t, SGX_DH_SESSION_DATA_SIZE, sgx_dh_session;
}
