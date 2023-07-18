// Copyright (c) 2022-2023 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![allow(
    clippy::missing_safety_doc,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_unsafe
)]

use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

/// This macro provides common byte-handling operations when the type being
/// wrapped is a struct containing a single fixed-size array of bytes.
///
/// This should be called from within a private submodule.
#[macro_export]
macro_rules! default_for_byte_struct {
    ($($byte_struct:ident, $fieldname:ident, $size:ident;)*) => {$(
        impl Default for $byte_struct {
            fn default() -> Self {
                Self{ $fieldname: [0u8; $size] }
            }
        }

    )*}
}

default_for_byte_struct! {
    sgx_report_data_t, d, SGX_REPORT_DATA_SIZE;
    sgx_measurement_t, m, SGX_HASH_SIZE;
    sgx_cpu_svn_t, svn, SGX_CPUSVN_SIZE;
    sgx_key_id_t, id, SGX_KEYID_SIZE;
    sgx_platform_info_t, platform_info, SGX_PLATFORM_INFO_SIZE;
}

impl Default for sgx_ql_att_key_id_t {
    fn default() -> Self {
        Self {
            id: Default::default(),
            version: Default::default(),
            mrsigner_length: Default::default(),
            mrsigner: [0u8; 48],
            prod_id: Default::default(),
            extended_prod_id: Default::default(),
            config_id: [0u8; 64],
            family_id: Default::default(),
            algorithm_id: Default::default(),
        }
    }
}

impl Default for sgx_att_key_id_ext_t {
    fn default() -> Self {
        Self {
            base: Default::default(),
            spid: Default::default(),
            att_key_type: Default::default(),
            reserved: [0u8; 80],
        }
    }
}

#[serde_as]
#[repr(C)]
#[derive(PartialEq, Hash, Clone, Eq, Copy, Debug, Serialize, Deserialize)]
pub struct sgx_report_data_t {
    #[serde_as(as = "Bytes")]
    pub d: [u8; SGX_REPORT_DATA_SIZE],
}

#[serde_as]
#[repr(C)]
#[derive(Hash, Copy, Eq, Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct sgx_report_body_t {
    pub cpu_svn: sgx_cpu_svn_t,
    pub misc_select: sgx_misc_select_t,
    pub reserved1: [u8; SGX_REPORT_BODY_RESERVED1_BYTES],
    pub isv_ext_prod_id: sgx_isvext_prod_id_t,
    pub attributes: sgx_attributes_t,
    pub mr_enclave: sgx_measurement_t,
    pub reserved2: [u8; SGX_REPORT_BODY_RESERVED2_BYTES],
    pub mr_signer: sgx_measurement_t,
    pub reserved3: [u8; SGX_REPORT_BODY_RESERVED3_BYTES],
    #[serde_as(as = "Bytes")]
    pub config_id: sgx_config_id_t,
    pub isv_prod_id: sgx_prod_id_t,
    pub isv_svn: sgx_isv_svn_t,
    pub config_svn: sgx_config_svn_t,
    #[serde_as(as = "Bytes")]
    pub reserved4: [u8; SGX_REPORT_BODY_RESERVED4_BYTES],
    pub isv_family_id: sgx_isvfamily_id_t,
    pub report_data: sgx_report_data_t,
}

impl Default for sgx_report_body_t {
    fn default() -> Self {
        Self {
            cpu_svn: Default::default(),
            misc_select: Default::default(),
            reserved1: [0u8; SGX_REPORT_BODY_RESERVED1_BYTES],
            isv_ext_prod_id: Default::default(),
            attributes: Default::default(),
            mr_enclave: Default::default(),
            reserved2: [0u8; SGX_REPORT_BODY_RESERVED2_BYTES],
            mr_signer: Default::default(),
            reserved3: [0u8; SGX_REPORT_BODY_RESERVED3_BYTES],
            config_id: [0u8; SGX_CONFIGID_SIZE],
            isv_prod_id: Default::default(),
            isv_svn: Default::default(),
            config_svn: Default::default(),
            reserved4: [0u8; SGX_REPORT_BODY_RESERVED4_BYTES],
            isv_family_id: Default::default(),
            report_data: Default::default(),
        }
    }
}

// Manually creating the bindings for `sgx_target_info_t` because of the need to derive serde for
// the `config_id` and `reserved3` fields. This structure is unlikely to change in size as the
// `reserved3` field is 384 bytes, appearing to be padding to make this structure 512 bytes. It is
// likely that any new fields will be taken from the `reserved3` space.
#[serde_as]
#[repr(C)]
#[derive(Eq, Hash, PartialEq, Clone, Debug, Copy, Serialize, Deserialize)]
pub struct sgx_target_info_t {
    pub mr_enclave: sgx_measurement_t,
    pub attributes: sgx_attributes_t,
    pub reserved1: [u8; SGX_TARGET_INFO_RESERVED1_BYTES],
    pub config_svn: sgx_config_svn_t,
    pub misc_select: sgx_misc_select_t,
    pub reserved2: [u8; SGX_TARGET_INFO_RESERVED2_BYTES],
    #[serde_as(as = "Bytes")]
    pub config_id: sgx_config_id_t,
    #[serde_as(as = "Bytes")]
    pub reserved3: [u8; SGX_TARGET_INFO_RESERVED3_BYTES],
}

impl Default for sgx_target_info_t {
    fn default() -> Self {
        Self {
            mr_enclave: Default::default(),
            attributes: Default::default(),
            reserved1: Default::default(),
            config_svn: Default::default(),
            misc_select: Default::default(),
            reserved2: Default::default(),
            config_id: [0u8; SGX_CONFIGID_SIZE],
            reserved3: [0u8; SGX_TARGET_INFO_RESERVED3_BYTES],
        }
    }
}

impl Default for sgx_key_request_t {
    fn default() -> Self {
        Self {
            key_name: Default::default(),
            key_policy: Default::default(),
            isv_svn: Default::default(),
            reserved1: Default::default(),
            cpu_svn: Default::default(),
            attribute_mask: Default::default(),
            key_id: Default::default(),
            misc_mask: Default::default(),
            config_svn: Default::default(),
            reserved2: [0u8; SGX_KEY_REQUEST_RESERVED2_BYTES],
        }
    }
}
