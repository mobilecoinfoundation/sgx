// Copyright (c) 2022 MobileCoin Foundation

//! This module contains logic to verify a DCAP quote

use mc_sgx_dcap_types::Quote3Error;
use mc_sgx_util::ResultInto;

/// Get the supplemental data size
pub fn supplemental_data_size() -> Result<usize, Quote3Error> {
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
