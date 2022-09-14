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

    /// The AAD(additional authenticated data) to use in the sealing.
    /// The Intel docs often refer to this as _MAC text_
    aad: Option<T>,
}

impl<T: AsRef<[u8]> + core::default::Default> SealedBuilder<T> {
    /// Construct a [`SealedBuilder`] from unsealed data
    ///
    /// # Arguments
    /// * `data` - The data to be encrypted/sealed
    pub fn new(data: T) -> Self {
        Self {
            data,
            ..Default::default()
        }
    }

    /// Build the [`Sealed`] object
    pub fn build(&self) -> Result<Sealed<Vec<u8>>> {
        let sealed_size = self.sealed_size()?;
        let mut sealed_data = vec![0; sealed_size];

        let (aad_pointer, aad_length) = match self.aad.as_ref() {
            Some(text) => (text.as_ref().as_ptr(), text.as_ref().len() as u32),
            None => (ptr::null(), 0),
        };

        unsafe {
            mc_sgx_tservice_sys::sgx_seal_data(
                aad_length,
                aad_pointer,
                self.data.as_ref().len() as u32,
                self.data.as_ref().as_ptr(),
                sealed_data.len() as u32,
                sealed_data.as_mut_ptr() as *mut sgx_sealed_data_t,
            )
        }
        .into_result()?;

        Sealed::try_from(sealed_data).map_err(|_| Error::Unexpected)
    }

    /// The AAD(additional authenticated data) to use in the sealing.
    ///
    /// The Intel docs also refers to AAD as _MAC text_
    ///
    /// # Arguments
    /// * `aad` - The AAD to add to the sealed data
    pub fn aad(&mut self, aad: T) -> &mut Self {
        self.aad = Some(aad);
        self
    }

    /// Returns the size needed to seal the data
    fn sealed_size(&self) -> Result<usize> {
        let aad_length = match &self.aad {
            Some(aad) => aad.as_ref().len() as u32,
            None => 0,
        };

        let result = unsafe {
            mc_sgx_tservice_sys::sgx_calc_sealed_data_size(
                aad_length,
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

pub trait Unseal<T> {
    /// The length (in bytes) needed to hold the decrypted text
    fn decrypted_text_len(&self) -> Result<usize>;

    /// Unseal the data in `self`
    fn unseal(&self) -> Result<T>;
}

impl<T: AsRef<[u8]>> Unseal<Vec<u8>> for Sealed<T> {
    fn decrypted_text_len(&self) -> Result<usize> {
        let result = unsafe {
            mc_sgx_tservice_sys::sgx_get_encrypt_txt_len(
                self.as_ref().as_ptr() as *const sgx_sealed_data_t
            )
        };
        match result {
            // Per the documentation, UINT32_MAX indicates an error
            u32::MAX => Err(Error::Unexpected),
            size => Ok(size as usize),
        }
    }

    fn unseal(&self) -> Result<Vec<u8>> {
        let data_length = self.decrypted_text_len()?;
        let mut data = vec![0; data_length];

        let mut data_length_u32 = data_length as u32;
        let mut mac_length_u32 = 0;
        unsafe {
            mc_sgx_tservice_sys::sgx_unseal_data(
                self.as_ref().as_ptr() as *const sgx_sealed_data_t,
                ptr::null_mut(),
                &mut mac_length_u32,
                data.as_mut_ptr(),
                &mut data_length_u32,
            )
        }
        .into_result()?;

        // While the lengths can be modified by `sgx_unseal_data`, we asked the
        // SGX interface at the top of the function for the required sizes.
        // If the sizes are different than we have unexpected behavior.
        if data_length != data_length_u32 as usize || mac_length_u32 != 0 {
            return Err(Error::Unexpected);
        }

        Ok(data)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem;

    #[test]
    fn sealed_data_size() {
        let mut builder = SealedBuilder::new(b"12345678".as_slice());
        builder.aad(b"123".as_slice());
        let expected_size =
            mem::size_of::<sgx_sealed_data_t>() + builder.data.len() + builder.aad.unwrap().len();
        assert_eq!(builder.sealed_size(), Ok(expected_size));
    }

    #[test]
    fn sealed_data_size_no_aad() {
        let builder = SealedBuilder::new(b"1234567".as_slice());
        let expected_size = mem::size_of::<sgx_sealed_data_t>() + builder.data.len();
        assert_eq!(builder.sealed_size(), Ok(expected_size));
    }

    #[test]
    fn decrypted_text_len_short() {
        let sgx_sealed_data = sgx_sealed_data_t::default();
        let bytes = test_utils::sealed_data_to_bytes(sgx_sealed_data, b"short", Some(b"one"));
        let data = Sealed::try_from(bytes.as_slice()).unwrap();
        assert_eq!(data.decrypted_text_len(), Ok(5));
    }

    #[test]
    fn decrypted_text_len_long() {
        let sgx_sealed_data = sgx_sealed_data_t::default();
        let bytes = test_utils::sealed_data_to_bytes(
            sgx_sealed_data,
            b"12345678901234567890",
            Some(b"where"),
        );
        let data = Sealed::try_from(bytes.as_slice()).unwrap();
        assert_eq!(data.decrypted_text_len(), Ok(20));
    }
}
