// Copyright (c) 2022 The MobileCoin Foundation

//! SGX Attributes types

use crate::new_type_wrapper;
use mc_sgx_core_sys_types::{sgx_attributes_t, sgx_misc_attribute_t, sgx_misc_select_t};

new_type_wrapper! {
    Attributes, sgx_attributes_t;
}

new_type_wrapper! {
    MiscellaneousSelect, sgx_misc_select_t;
}

new_type_wrapper! {
    MiscellaneousAttribute, sgx_misc_attribute_t;
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;

    #[test]
    fn sgx_attributes_to_attributes() {
        let sgx_attributes = sgx_attributes_t { flags: 1, xfrm: 2 };
        let attributes: Attributes = sgx_attributes.clone().into();
        assert_eq!(attributes.0, sgx_attributes);
    }

    #[test]
    fn attributes_to_sgx_attributes() {
        let attributes = Attributes(sgx_attributes_t { flags: 9, xfrm: 12 });
        let sgx_attributes: sgx_attributes_t = attributes.into();
        assert_eq!(sgx_attributes, sgx_attributes_t { flags: 9, xfrm: 12 });
    }
}
