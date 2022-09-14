// Copyright (c) 2022 The MobileCoin Foundation
//! Functions used for sealing and unsealing of secrets

use alloc::{vec, vec::Vec};
pub use core::ptr;
pub use mc_sgx_core_types::{Error, Result};
pub use mc_sgx_tservice_sys::sgx_calc_sealed_data_size;
pub use mc_sgx_tservice_sys_types::sgx_sealed_data_t;
pub use mc_sgx_tservice_types::Sealed;
use mc_sgx_util::ResultInto;

/// Sealed data builder
#[derive(Debug, Clone, Hash, PartialEq, Eq, Default)]
pub struct SealedBuilder<T> {
    /// The data to be encrypted/sealed
    data: T,

    /// The MAC text that will not be encrypted
    mac: Option<T>,
}

impl<T: AsRef<[u8]> + core::default::Default> SealedBuilder<T> {
    /// A [`SealedBuilder`] from
    ///
    /// # Arguments
    /// * `data` - The data to be encrypted/sealed
    /// * `mac` - The MAC text.  Will not be encrypted
    pub fn new(data: T) -> Self {
        Self {
            data,
            ..Default::default()
        }
    }

    /// Build the [`Sealed`] object
    pub fn build(self) -> Result<Sealed<Vec<u8>>> {
        let sealed_size = self.sealed_size()?;
        let mut sealed_data = vec![0; sealed_size];

        let (mac_pointer, mac_length) = match self.mac.as_ref() {
            Some(text) => (text.as_ref().as_ptr(), text.as_ref().len() as u32),
            None => (ptr::null(), 0),
        };

        unsafe {
            mc_sgx_tservice_sys::sgx_seal_data(
                mac_length,
                mac_pointer,
                self.data.as_ref().len() as u32,
                self.data.as_ref().as_ptr(),
                sealed_data.len() as u32,
                sealed_data.as_mut_ptr() as *mut sgx_sealed_data_t,
            )
        }
        .into_result()?;

        Sealed::try_from(sealed_data).map_err(|_| Error::Unexpected)
    }

    /// MAC text to add to the sealed data
    ///
    /// The MAC text is also referred to as AAD(Additional Authenticated data)
    ///
    /// # Arguments
    /// * `mac_text` - The MAC text to add to the sealed data
    pub fn mac_text(mut self, mac_text: T) -> Self {
        self.mac = Some(mac_text);
        self
    }

    /// Returns the size needed to seal the data
    fn sealed_size(&self) -> Result<usize> {
        let mac_length = match &self.mac {
            Some(mac) => mac.as_ref().len() as u32,
            None => 0,
        };

        let result = unsafe {
            mc_sgx_tservice_sys::sgx_calc_sealed_data_size(
                mac_length,
                self.data.as_ref().len() as u32,
            )
        };

        match result {
            // Per the documentation, UINT32_MAX indicates an error
            u32::MAX => Err(Error::Unexpected),
            size => Ok(size as usize),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem;

    #[test]
    fn sealed_data_size() {
        let builder = SealedBuilder::new(b"12345678".as_slice()).mac_text(b"123".as_slice());
        let expected_size =
            mem::size_of::<sgx_sealed_data_t>() + builder.data.len() + builder.mac.unwrap().len();
        assert_eq!(builder.sealed_size(), Ok(expected_size));
    }

    #[test]
    fn sealed_data_size_no_mac() {
        let builder = SealedBuilder::new(b"1234567".as_slice());
        let expected_size = mem::size_of::<sgx_sealed_data_t>() + builder.data.len();
        assert_eq!(builder.sealed_size(), Ok(expected_size));
    }
}
