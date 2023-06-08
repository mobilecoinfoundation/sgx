// Copyright (c) 2023 The MobileCoin Foundation

//! Provides functionality to get collateral for a [`Quote3`].

use crate::{Error, LoadPolicyInitializer, PathInitializer};
use mc_sgx_dcap_sys_types::sgx_ql_qve_collateral_t;
use mc_sgx_dcap_types::Quote3;
use mc_sgx_util::ResultInto;
use std::mem;

/// The minimum size from `tee_qv_get_collateral` for the pointer to contain a
/// valid collateral.
const MIN_SGX_COLLATERAL_SIZE: u32 = mem::size_of::<sgx_ql_qve_collateral_t>() as u32;

/// A pointer to [`sgx_ql_qve_collateral_t`] that will free on drop
#[derive(Debug, PartialEq)]
pub struct CollateralPointer {
    collateral: *mut sgx_ql_qve_collateral_t,
}

impl Drop for CollateralPointer {
    fn drop(&mut self) {
        unsafe {
            mc_sgx_dcap_quoteverify_sys::tee_qv_free_collateral(self.collateral as *mut u8);
        }
    }
}

/// Collateral is additional data that is used in verification.
///
/// The data can be retrieved from `tee_qv_get_collateral()` or from the
/// following individual endpoints:
/// - <https://api.portal.trustedservices.intel.com/documentation#pcs-revocation-v4>
/// - <https://api.portal.trustedservices.intel.com/documentation#pcs-tcb-info-v4>
/// - <https://api.portal.trustedservices.intel.com/documentation#pcs-enclave-identity-v4>
/// - <https://certificates.trustedservices.intel.com/IntelSGXRootCA.der>
pub trait Collateral {
    /// Get the collateral for `self`.
    fn collateral(&self) -> Result<CollateralPointer, Error>;
}

impl<T: AsRef<[u8]>> Collateral for Quote3<T> {
    fn collateral(&self) -> Result<CollateralPointer, Error> {
        PathInitializer::ensure_initialized()?;
        LoadPolicyInitializer::ensure_initialized()?;

        let quote_slice = self.as_ref();
        let mut sgx_collateral = core::ptr::null_mut();
        let mut collateral_size = 0;

        unsafe {
            mc_sgx_dcap_quoteverify_sys::tee_qv_get_collateral(
                quote_slice.as_ptr(),
                quote_slice.len() as u32,
                &mut sgx_collateral,
                &mut collateral_size,
            )
        }
        .into_result()?;

        // The `collateral_size` is the size of the base structure plus the size
        // of all the bytes that the members point to. Thus it should always be
        // greater than `MIN_SGX_COLLATERAL_SIZE`.
        if collateral_size < MIN_SGX_COLLATERAL_SIZE {
            return Err(Error::CollateralSizeTooSmall(
                MIN_SGX_COLLATERAL_SIZE,
                collateral_size,
            ));
        }

        Ok(CollateralPointer {
            collateral: sgx_collateral as *mut _,
        })
    }
}
