// Copyright (c) 2022 The MobileCoin Foundation
//! FFI functions for the SGX SDK trusted service library (tservice).

#![no_std]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use mc_sgx_core_sys_types::{
    sgx_attributes_t, sgx_key_128bit_t, sgx_key_request_t, sgx_misc_select_t, sgx_report_data_t,
    sgx_report_t, sgx_status_t, sgx_target_info_t,
};
use mc_sgx_service_sys_types::{
    sgx_dh_msg1_t, sgx_dh_msg2_t, sgx_dh_msg3_t, sgx_dh_session_enclave_identity_t,
    sgx_dh_session_role_t, sgx_dh_session_t, sgx_report2_mac_struct_t, sgx_sealed_data_t,
};
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    const SEALED_META_SIZE: u32 = 560;
    #[test]
    fn calculate_sealed_all_0() {
        let mac_size = 0;
        let text_size = 0;
        let size = unsafe { sgx_calc_sealed_data_size(mac_size, text_size) };
        assert_eq!(size, mac_size + text_size + SEALED_META_SIZE);
    }

    #[test]
    fn calculate_sealed_20_30() {
        let mac_size = 20;
        let text_size = 30;
        let size = unsafe { sgx_calc_sealed_data_size(mac_size, text_size) };
        assert_eq!(size, mac_size + text_size + SEALED_META_SIZE);
    }

    #[test]
    fn calculate_sealed_9999_88888() {
        let mac_size = 9999;
        let text_size = 88888;
        let size = unsafe { sgx_calc_sealed_data_size(mac_size, text_size) };
        assert_eq!(size, mac_size + text_size + SEALED_META_SIZE);
    }
}
