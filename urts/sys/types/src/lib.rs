// Copyright (c) 2022 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use mc_sgx_core_sys_types::{
    sgx_attributes_t, sgx_config_id_t, sgx_config_svn_t, sgx_misc_select_t,
};
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

impl Default for sgx_kss_config_t {
    fn default() -> sgx_kss_config_t {
        sgx_kss_config_t {
            config_id: [0; 64],
            config_svn: 0,
        }
    }
}
