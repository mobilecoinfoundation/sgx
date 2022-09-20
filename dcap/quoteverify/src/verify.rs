// Copyright (c) 2022 MobileCoin Foundation

//! This module contains logic to verify a DCAP quote

use mc_sgx_core_types::{BaseQuote, Quote};
use mc_sgx_dcap_sys_types::{sgx_ql_qv_result_t, time_t};
use mc_sgx_dcap_types::Quote3Error;
use mc_sgx_util::ResultInto;
use std::{
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};

pub trait Verify: BaseQuote {
    fn verify(&self) -> Result<(), Quote3Error> {
        let raw_quote = self.raw_quote();
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let mut expiration_status = 0;
        let mut quote_status = sgx_ql_qv_result_t::SGX_QL_QV_RESULT_MAX;

        unsafe {
            mc_sgx_dcap_quoteverify_sys::sgx_qv_verify_quote(
                raw_quote.as_ref().as_ptr(),
                raw_quote.as_ref().len() as u32,
                ptr::null(),
                since_the_epoch.as_secs() as time_t,
                &mut expiration_status,
                &mut quote_status,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
            )
        }
        .into_result()
    }
}

impl<'a> Verify for Quote<'a> {}

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
    const QUOTE: &[u8] = include_bytes!("../tests/quote.dat");

    #[test]
    fn supplemental_size() {
        let size = supplemental_data_size().unwrap();
        assert_eq!(size, mem::size_of::<sgx_ql_qv_supplemental_t>());
    }

    #[test]
    fn verify_sample_quote_is_unsupported_data() {
        let quote: Quote = QUOTE.into();
        let result = quote.verify();

        // THe test quote is not a cert type 5.  In order to fully support a
        // cert type 5 one needs a PCCS running, which requires more from the
        // test environment.  The intent is to test the wrapping of
        // `sgx_qv_verify_quote`, not the full behavior of `sgx_qv_verify_quote`
        assert_eq!(result, Err(Quote3Error::UnsupportedQuoteCertificationData));
    }
}
