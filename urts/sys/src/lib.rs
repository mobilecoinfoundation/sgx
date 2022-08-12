// Copyright (c) 2022 The MobileCoin Foundation
// See https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_Enclave_Common_Loader_API_Reference.pdf
//
#![feature(c_size_t)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use core::ffi::c_size_t as size_t;
use mc_sgx_core_sys_types::{sgx_status_t, sgx_target_info_t};
use mc_sgx_urts_sys_types::{sgx_enclave_id_t, sgx_launch_token_t, sgx_misc_attribute_t};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::raw::c_int, ptr};
    use test_enclave::{ecall_add_2, ENCLAVE};

    #[test]
    fn bindings_can_be_used_to_call_enclave_functions() {
        let mut enclave_id: sgx_enclave_id_t = 0;
        let mut bytes = ENCLAVE.to_vec();
        let result = unsafe {
            sgx_create_enclave_from_buffer_ex(
                bytes.as_mut_ptr(),
                bytes.len().try_into().unwrap(),
                0,
                &mut enclave_id,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        };
        assert_eq!(result, sgx_status_t::SGX_SUCCESS);

        let mut sum: c_int = 0;
        let result = unsafe { ecall_add_2(enclave_id, 10, &mut sum) };
        let destroy_result = unsafe { sgx_destroy_enclave(enclave_id) };
        assert_eq!(result, sgx_status_t::SGX_SUCCESS);
        assert_eq!(destroy_result, sgx_status_t::SGX_SUCCESS);
        assert_eq!(sum, 10 + 2);
    }
}
