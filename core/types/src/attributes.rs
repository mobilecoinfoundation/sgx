// Copyright (c) 2022 The MobileCoin Foundation

//! SGX Attributes types

use crate::new_type_accessors_impls;
use mc_sgx_core_sys_types::{sgx_attributes_t, sgx_misc_attribute_t, sgx_misc_select_t};

#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Attributes(sgx_attributes_t);
new_type_accessors_impls! {
    Attributes, sgx_attributes_t;
}

impl Default for Attributes {
    fn default() -> Self {
        Attributes(sgx_attributes_t { flags: 0, xfrm: 0 })
    }
}

impl Attributes {
    /// Set the `flags` for the attributes
    ///
    /// # Arguments
    ///
    /// * `flags` - The flags to be set in the attributes
    pub fn set_flags(mut self, flags: u64) -> Self {
        self.0.flags = flags;
        self
    }

    /// Set the `transform` for the attributes
    ///
    /// # Arguments
    ///
    /// * `transmform` - The transform to be set to the `xfrm` in the attributes
    pub fn set_transform(mut self, transform: u64) -> Self {
        self.0.xfrm = transform;
        self
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct MiscellaneousSelect(sgx_misc_select_t);
new_type_accessors_impls! {
    MiscellaneousSelect, sgx_misc_select_t;
}

impl MiscellaneousSelect {
    pub fn new(select: u32) -> Self {
        Self(select)
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct MiscellaneousAttribute(sgx_misc_attribute_t);
new_type_accessors_impls! {
    MiscellaneousAttribute, sgx_misc_attribute_t;
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;
    use yare::parameterized;

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

    #[parameterized(
    three_five = { 3, 5 },
    four_nine = { 4, 9 },
    )]
    fn attributes_builder(flags: u64, transform: u64) {
        let attributes = Attributes::default()
            .set_flags(flags)
            .set_transform(transform);
        assert_eq!(attributes.0.flags, flags);
        assert_eq!(attributes.0.xfrm, transform);
    }
}
