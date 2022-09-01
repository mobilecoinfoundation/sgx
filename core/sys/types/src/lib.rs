// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![allow(
    clippy::missing_safety_doc,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]

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
