// Copyright (c) 2022 The MobileCoin Foundation
//! Functions used for sealing and unsealing of secrets

use alloc::{vec, vec::Vec};
pub use core::ptr;
pub use mc_sgx_core_types::{Error, Result};
pub use mc_sgx_tservice_sys::sgx_calc_sealed_data_size;
pub use mc_sgx_tservice_sys_types::sgx_sealed_data_t;
pub use mc_sgx_tservice_types::Sealed;
use mc_sgx_util::ResultInto;

/// Handles the logic to seal data in an SGX enclave
pub trait Seal<T> {
    /// Returns the size needed to seal the `data`
    ///
    /// # Arguments
    /// * `data` - The data to be sealed
    fn sealed_data_size(&self) -> Result<usize>;

    /// Seals the data
    fn seal_data(&self) -> Result<Sealed<T>>;
}

/// Unsealed Data
///
/// A plain old data type (POD) of the component pieces of the data stored in
/// [`sgx_sealed_data_t`]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Unsealed<T> {
    /// The data to be encrypted/sealed
    pub data: T,

    /// The MAC text that will not be encrypted
    pub mac: Option<T>,
}

impl<T: AsRef<[u8]>> Unsealed<T> {
    /// An [`Unsealed`] from the components
    ///
    /// # Arguments
    /// * `data` - The data to be encrypted/sealed
    /// * `mac` - The MAC text.  Will not be encrypted
    pub fn new(data: T, mac: Option<T>) -> Self {
        Self { data, mac }
    }

    /// The length of the combined [`Unsealed.data`] and [`Unsealed.mac`]
    pub fn len(&self) -> usize {
        let mac_length = match &self.mac {
            None => 0,
            Some(text) => text.as_ref().len(),
        };
        mac_length + self.data.as_ref().len()
    }

    /// Is the unsealed data empty?
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: AsRef<[u8]>> Seal<Vec<u8>> for Unsealed<T> {
    /// Returns the size needed to seal the `data`
    ///
    /// # Arguments
    /// * `data` - The data to be sealed
    fn sealed_data_size(&self) -> Result<usize> {
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

    fn seal_data(&self) -> Result<Sealed<Vec<u8>>> {
        let sealed_size = self.sealed_data_size()?;
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
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem;

    #[test]
    fn sealed_data_size() {
        let data = Unsealed::new(b"12345678".as_slice(), Some(b"123".as_slice()));
        let expected_size = mem::size_of::<sgx_sealed_data_t>() + data.len();
        assert_eq!(data.sealed_data_size(), Ok(expected_size));
    }

    #[test]
    fn sealed_data_size_no_mac() {
        let data = Unsealed::new(b"1234567", None);
        let expected_size = mem::size_of::<sgx_sealed_data_t>() + data.len();
        assert_eq!(data.sealed_data_size(), Ok(expected_size));
    }
}
