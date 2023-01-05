// Copyright (c) 2022-2023 MobileCoin Foundation

//! This module contains logic to assist in verifying a DCAP quote

use crate::{quote_enclave::LoadPolicyInitializer, Error, PathInitializer};
use mc_sgx_util::ResultInto;

/// Get the supplemental data size
///
/// Note: This will initialize the [`PathInitializer`] and
///   [`LoadPolicyInitializer`] to the defaults if they have not been
///   initialized yet. Attempts to initialize [`PathInitializer`] or
///   [`LoadPolicyInitializer`] after calling this function will result in
///   an error.
///
/// # Errors
///
/// [`Error::QuoteLibrary`] if there is any error retrieving the supplemental size from
/// SGX.
pub fn supplemental_data_size() -> Result<usize, Error> {
    PathInitializer::ensure_initialized()?;
    LoadPolicyInitializer::ensure_initialized()?;
    let mut size: u32 = 0;
    unsafe { mc_sgx_dcap_quoteverify_sys::sgx_qv_get_quote_supplemental_data_size(&mut size) }
        .into_result()?;
    Ok(size as usize)
}

#[cfg(test)]
mod test {
    use super::*;
    use core::mem;
    use mc_sgx_dcap_sys_types::sgx_ql_qv_supplemental_t;

    #[test]
    fn supplemental_size() {
        let size = supplemental_data_size().unwrap();
        assert_eq!(size, mem::size_of::<sgx_ql_qv_supplemental_t>());
    }
}
