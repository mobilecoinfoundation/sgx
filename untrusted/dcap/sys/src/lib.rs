// Copyright (c) 2022 The MobileCoin Foundation
// See https://download.01.org/intel-sgx/sgx-dcap/1.13/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
//
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

// pub use mc_sgx_dcap_sys_types::{
//     sgx_enclave_id_t, sgx_launch_token_t, sgx_misc_attribute_t, sgx_status_t, sgx_target_info_t,
//     size_t,
// };

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
