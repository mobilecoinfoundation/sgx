// Copyright (c) 2022 The MobileCoin Foundation

//! SGX key request rust types

use crate::{new_type_wrapper, Attributes, MiscellaneousSelect};
use mc_sgx_core_sys_types::{
    sgx_config_svn_t, sgx_cpu_svn_t, sgx_isv_svn_t, sgx_key_id_t, sgx_key_request_t,
};

new_type_wrapper! {
    CpuSvn, sgx_cpu_svn_t;
}

impl Default for CpuSvn {
    fn default() -> Self {
        CpuSvn(sgx_cpu_svn_t { svn: [0; 16] })
    }
}

new_type_wrapper! {
    KeyRequest, sgx_key_request_t;
}

impl Default for KeyRequest {
    fn default() -> Self {
        KeyRequest(sgx_key_request_t {
            key_name: 0,
            key_policy: 0,
            isv_svn: 0,
            reserved1: 0,
            cpu_svn: CpuSvn::default().into(),
            attribute_mask: Attributes::default().into(),
            // TODO ideally this should be random
            key_id: sgx_key_id_t { id: [0; 32] },
            misc_mask: MiscellaneousSelect::default().into(),
            config_svn: 0,
            reserved2: [0; 434],
        })
    }
}

impl KeyRequest {
    /// Set the key name to use in the key request
    ///
    /// # Arguments
    ///
    /// * `key_name`: The key name to use
    pub fn set_key_name(mut self, key_name: u16) -> Self {
        self.0.key_name = key_name;
        self
    }

    /// Set the key policy to use in the key request
    ///
    /// # Arguments
    ///
    /// * `key_policy`: The key policy to use
    pub fn set_key_policy(mut self, key_policy: u16) -> Self {
        self.0.key_policy = key_policy;
        self
    }

    /// Set the ISV(Individual Software Vendor) SVN (Security Version Number) of
    /// the key request
    ///
    /// # Arguments
    ///
    /// * `isv_svn`: The ISV SVN to use
    pub fn set_isv_svn(mut self, isv_svn: sgx_isv_svn_t) -> Self {
        self.0.isv_svn = isv_svn;
        self
    }

    /// Set the CPU SVN (Security Version Number) of the key request
    ///
    /// # Arguments
    ///
    /// * `cpu_svn`: The CPU SVN to use
    pub fn set_cpu_svn(mut self, cpu_svn: &CpuSvn) -> Self {
        self.0.cpu_svn = cpu_svn.clone().into();
        self
    }

    /// Set the attributes of the key request
    ///
    /// # Arguments
    ///
    /// * `attributes`: The attributes to use
    pub fn set_attributes(mut self, attributes: &Attributes) -> Self {
        self.0.attribute_mask = attributes.clone().into();
        self
    }

    /// Set the miscellaneous select values
    ///
    /// # Arguments
    ///
    /// * `miscellaneous_select`: The miscellaneous select values to use
    pub fn set_miscellaneous_select(mut self, miscellaneous_select: &MiscellaneousSelect) -> Self {
        self.0.misc_mask = miscellaneous_select.clone().into();
        self
    }

    /// Set the config SVN (Security Version Number) of the key request
    ///
    /// # Arguments
    ///
    /// * `config_svn`: The config SVN to use
    pub fn set_config_svn(mut self, config_svn: sgx_config_svn_t) -> Self {
        self.0.config_svn = config_svn;
        self
    }
}

#[cfg(test)]
mod test {
    extern crate std;
    use super::*;

    #[test]
    fn default_key_request_all_zero() {
        let request = KeyRequest::default();

        assert_eq!(request.0.key_name, 0);
        assert_eq!(request.0.key_policy, 0);
        assert_eq!(request.0.isv_svn, 0);
        assert_eq!(request.0.cpu_svn.svn, [0; 16]);
        assert_eq!(request.0.attribute_mask.flags, 0);
        assert_eq!(request.0.attribute_mask.xfrm, 0);
        assert_eq!(request.0.misc_mask, 0);
        assert_eq!(request.0.config_svn, 0);
    }

    #[test]
    fn build_key_request() {
        let request = KeyRequest::default()
            .set_key_name(1)
            .set_key_policy(2)
            .set_isv_svn(3)
            .set_cpu_svn(&CpuSvn(sgx_cpu_svn_t { svn: [4; 16] }))
            .set_attributes(&Attributes::default().set_flags(5).set_transform(6))
            .set_miscellaneous_select(&7.into())
            .set_config_svn(8);

        assert_eq!(request.0.key_name, 1);
        assert_eq!(request.0.key_policy, 2);
        assert_eq!(request.0.isv_svn, 3);
        assert_eq!(request.0.cpu_svn.svn, [4; 16]);
        assert_eq!(request.0.attribute_mask.flags, 5);
        assert_eq!(request.0.attribute_mask.xfrm, 6);
        assert_eq!(request.0.misc_mask, 7);
        assert_eq!(request.0.config_svn, 8);
    }
}
