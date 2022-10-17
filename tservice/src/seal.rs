// Copyright (c) 2022 The MobileCoin Foundation
//! Functions used for sealing and unsealing of secrets

use alloc::{format, string::String, vec, vec::Vec};
use core::{mem, ptr, result::Result as CoreResult};
use mc_sgx_core_types::{Attributes, KeyPolicy, MiscellaneousSelect};
use mc_sgx_tservice_sys_types::sgx_sealed_data_t;
pub use mc_sgx_tservice_types::Sealed;
use mc_sgx_util::ResultInto;

// Default values used in `sgx_seal_data_ex` to behave the same as
// `sgx_seal_data`. See
// https://download.01.org/intel-sgx/sgx-linux/2.17.1/docs/Intel_SGX_Developer_Reference_Linux_2.17.1_Open_Source.pdf
// Some fo these values can also be seen in the internal SGX SDK headers:
// - TSEAL_DEFAULT_FLAGSMASK => DEFAULT_ATTRIBUTES_FLAGS_FOR_SEAL
// - TSEAL_DEFAULT_MISCMASK => DEFAULT_MISCELLANEOUS_MASK_FOR_SEAL
const DEFAULT_MISCELLANEOUS_MASK_FOR_SEAL: u32 = 0xF0000000;
const DEFAULT_ATTRIBUTES_FLAGS_FOR_SEAL: u64 = 0xFF0000000000000B;
const DEFAULT_KEY_POLICY_FOR_SEAL: KeyPolicy = KeyPolicy::MRSIGNER;

pub type Result<T> = CoreResult<T, Error>;

#[derive(Clone, Debug, displaydoc::Display, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum Error {
    /// Error from SGX function {0}
    Sgx(mc_sgx_core_types::Error),
    /// FFI error {0}
    Ffi(mc_sgx_core_types::FfiError),
    /** The combined plaintext ({data_size}) and authenticated data
     *  ({aad_size}) sizes are larger than 4GiB */
    DataAadOverflow { data_size: usize, aad_size: usize },
    /** The destination buffer must be at least {needed_size} bytes,
     *  {buffer_size} was given */
    UnsealedBufferTooSmall {
        buffer_size: usize,
        needed_size: usize,
    },
    /// Unexpected behavior from the SGX interface: {0}
    Unexpected(String),
}

impl From<mc_sgx_core_types::Error> for Error {
    fn from(src: mc_sgx_core_types::Error) -> Self {
        Error::Sgx(src)
    }
}

impl From<mc_sgx_core_types::FfiError> for Error {
    fn from(src: mc_sgx_core_types::FfiError) -> Self {
        Error::Ffi(src)
    }
}

/// Sealed data builder
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SealedBuilder<T> {
    /// The data to be encrypted/sealed
    data: T,

    /// The key policy to use when sealing
    policy: KeyPolicy,

    /// The AAD(additional authenticated data) to use in the sealing.
    /// The Intel docs often refer to this as _MAC text_
    aad: Option<T>,
}

impl<T: AsRef<[u8]> + Default> SealedBuilder<T> {
    /// Construct a [`SealedBuilder`] from unsealed data
    ///
    /// # Arguments
    /// * `data` - The data to be encrypted/sealed
    pub fn new(data: T) -> Self {
        Self {
            data,
            policy: DEFAULT_KEY_POLICY_FOR_SEAL,
            aad: None,
        }
    }

    /// Build the [`Sealed`] object
    pub fn build(&self) -> Result<Sealed<Vec<u8>>> {
        self.validate_inputs()?;
        let sealed_size = self.sealed_size()?;
        let mut sealed_data = vec![0; sealed_size];

        let (aad_pointer, aad_length) = match self.aad.as_ref() {
            Some(text) => (text.as_ref().as_ptr(), text.as_ref().len() as u32),
            None => (ptr::null(), 0),
        };

        // Currently see no reason to expose attributes as an option.  Exposing
        // the attributes will require some error handling and normalization
        let attributes = Attributes::default().set_flags(DEFAULT_ATTRIBUTES_FLAGS_FOR_SEAL);

        // Since `misc_mask` is reserved for future extension omitting from
        // the builder
        let misc_mask = MiscellaneousSelect::from(DEFAULT_MISCELLANEOUS_MASK_FOR_SEAL);
        unsafe {
            mc_sgx_tservice_sys::sgx_seal_data_ex(
                self.policy.bits(),
                attributes.into(),
                misc_mask.into(),
                aad_length,
                aad_pointer,
                self.data.as_ref().len() as u32,
                self.data.as_ref().as_ptr(),
                sealed_data.len() as u32,
                sealed_data.as_mut_ptr() as *mut sgx_sealed_data_t,
            )
        }
        .into_result()?;

        Ok(Sealed::try_from(sealed_data)?)
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

    /// Set the key policy to use for the sealed data
    ///
    /// # Arguments
    /// * `policy` - The key policy to use
    pub fn key_policy(&mut self, policy: KeyPolicy) -> &mut Self {
        self.policy = policy;
        self
    }

    /// Returns the size needed to seal the data
    fn sealed_size(&self) -> Result<usize> {
        let aad_size = match &self.aad {
            Some(aad) => aad.as_ref().len() as u32,
            None => 0,
        };

        let data_size = self.data.as_ref().len() as u32;

        Self::check_sealed_size_overflow(data_size as u64, aad_size as u64)?;

        let result = unsafe { mc_sgx_tservice_sys::sgx_calc_sealed_data_size(aad_size, data_size) };

        match result {
            // Per the documentation, UINT32_MAX indicates an error
            // This shouldn't happen with the `check_sealed_size_overflow` call
            // above, but the logic is kept here in case the SGX SDK adds other
            // validation checks that aren't covered in
            // `check_sealed_size_overflow`.
            u32::MAX => Err(Error::DataAadOverflow {
                data_size: data_size as usize,
                aad_size: aad_size as usize,
            }),
            size => Ok(size as usize),
        }
    }

    fn validate_inputs(&self) -> Result<()> {
        Ok(())
    }

    fn check_sealed_size_overflow(data_size: u64, aad_size: u64) -> Result<()> {
        let overall_size = data_size + aad_size + mem::size_of::<sgx_sealed_data_t>() as u64;

        // NB: There appears to be an off by one in the
        // `sgx_calc_sealed_data_size()`.  It conditions for `a > MAX - b`.
        // Without overflows this can be interpreted as `a + b > MAX`.  This
        // means when `a + b == MAX` it follows the happy path returning MAX.
        if overall_size >= u32::MAX as u64 {
            Err(Error::DataAadOverflow {
                data_size: data_size as usize,
                aad_size: aad_size as usize,
            })
        } else {
            Ok(())
        }
    }
}

/// Unseal data.
///
/// Functionality to convert sealed (encrypted) data to unsealed, unencrypted
pub trait Unseal: AsRef<[u8]> {
    /// The length (in bytes) needed to hold the decrypted text
    fn decrypted_text_len(&self) -> Result<usize> {
        let result = unsafe {
            mc_sgx_tservice_sys::sgx_get_encrypt_txt_len(
                self.as_ref().as_ptr() as *const sgx_sealed_data_t
            )
        };
        match result {
            // Per the documentation, UINT32_MAX indicates an error, however
            // this should only happen if we passed in a NULL pointer, which we
            // prevent with the trait bounds
            u32::MAX => Err(Error::Unexpected(String::from(
                "Failed to get the decrypted text length.",
            ))),
            size => Ok(size as usize),
        }
    }

    /// Unseal the data in `self`
    ///
    /// Returns the unsealed data into the provided `buffer`.  The returned
    /// slice will be the exact size of the unsealed data.
    ///
    /// # Arguments
    /// * `buffer` - The buffer to output the unsealed data into.  `buffer`
    ///   needs to be at least as big as
    ///   [`decrypted_text_len`](Unseal::decrypted_text_len)
    fn unseal<'a>(&self, buffer: &'a mut [u8]) -> Result<&'a mut [u8]> {
        let data_length = self.decrypted_text_len()?;
        if buffer.len() < data_length {
            return Err(Error::UnsealedBufferTooSmall {
                buffer_size: buffer.len(),
                needed_size: data_length,
            });
        }

        let mut data_length_u32 = data_length as u32;
        let mut mac_length_u32 = 0;
        unsafe {
            mc_sgx_tservice_sys::sgx_unseal_data(
                self.as_ref().as_ptr() as *const sgx_sealed_data_t,
                ptr::null_mut(),
                &mut mac_length_u32,
                buffer.as_mut_ptr(),
                &mut data_length_u32,
            )
        }
        .into_result()?;

        // While the lengths can be modified by `sgx_unseal_data`, we asked the
        // SGX interface at the top of the function for the required sizes.
        // If the sizes are different than we have unexpected behavior.
        if data_length != data_length_u32 as usize || mac_length_u32 != 0 {
            return Err(Error::Unexpected(format!(
                "'sgx_unseal_data()' set the data length to {} when given length {}",
                data_length_u32, data_length
            )));
        }

        Ok(&mut buffer[..data_length])
    }

    /// Unseal the data in `self`
    fn unseal_to_vec(&self) -> Result<Vec<u8>> {
        let data_length = self.decrypted_text_len()?;
        let mut data = vec![0; data_length];
        self.unseal(data.as_mut_slice())?;
        Ok(data)
    }
}

impl<T: AsRef<[u8]>> Unseal for Sealed<T> {}

#[cfg(test)]
mod test {
    use super::*;
    use mc_sgx_tservice_types::test_utils;
    use yare::parameterized;

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

    #[parameterized(
    zeros = {0, 0},
    one_two = {1, 2},
    maxed_data = {(u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>()) - 1, 0},
    maxed_aad = {0, (u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>()) - 1},
    half_way = {(u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>()) / 2, (u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>()) / 2},
    almost_maxed_data_one_aad = {(u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>()) - 2, 1},
    )]
    fn no_sealed_size_overflow(data_size: usize, aad_size: usize) {
        assert_eq!(
            SealedBuilder::<&[u8]>::check_sealed_size_overflow(data_size as u64, aad_size as u64),
            Ok(())
        );
    }

    #[parameterized(
    data_overflow = {u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>(), 0},
    aad_overflow = {0, u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>()},
    half_way = {(u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>()) / 2 + 1, (u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>()) / 2},
    data_overflow_one_aad = {(u32::MAX as usize - mem::size_of::<sgx_sealed_data_t>()) - 1, 1},
    )]
    fn sealed_size_overflow(data_size: usize, aad_size: usize) {
        assert_eq!(
            SealedBuilder::<&[u8]>::check_sealed_size_overflow(data_size as u64, aad_size as u64),
            Err(Error::DataAadOverflow {
                data_size,
                aad_size
            })
        );
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
