// Copyright (c) 2022 The MobileCoin Foundation
//! Rust wrappers for functionality in the SGX SDK trusted service library
//! (tservice).

use mc_sgx_service_sys::sgx_calc_sealed_data_size;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidSealedDataSize,
}

/// Creates sealed data to be stored for later use by the enclave
pub struct SealedDataBuilder<'a> {
    text: &'a [u8],
    mac: &'a [u8],
}

impl<'a> SealedDataBuilder<'a> {
    pub fn new(text: &'a [u8], mac: &'a [u8]) -> Self {
        SealedDataBuilder { text, mac }
    }

    // TODO move to private when, the rest of the sealing logic comes in
    pub fn size(&self) -> Result<usize, Error> {
        let size =
            unsafe { sgx_calc_sealed_data_size(self.mac.len() as u32, self.text.len() as u32) };
        match size {
            0xFFFFFFFF => Err(Error::InvalidSealedDataSize),
            size => Ok(size as usize),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEALED_META_SIZE: usize = 560;

    #[test]
    fn size_15_23() {
        const TEXT_SIZE: usize = 15;
        const MAC_SIZE: usize = 23;
        let size = SealedDataBuilder::new(&[3; TEXT_SIZE], &[0; MAC_SIZE]).size();
        assert_eq!(size, Ok(SEALED_META_SIZE + TEXT_SIZE + MAC_SIZE));
    }

    #[test]
    fn size_352_963() {
        const TEXT_SIZE: usize = 352;
        const MAC_SIZE: usize = 963;
        let size = SealedDataBuilder::new(&[3; TEXT_SIZE], &[0; MAC_SIZE]).size();
        assert_eq!(size, Ok(SEALED_META_SIZE + TEXT_SIZE + MAC_SIZE));
    }
}
