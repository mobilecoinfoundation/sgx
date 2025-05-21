// Copyright (c) 2023-2025 The MobileCoin Foundation

//! Provides functionality to get collateral for a [`Quote3`].

use crate::{Error, LoadPolicyInitializer, PathInitializer};
use mc_sgx_dcap_sys_types::sgx_ql_qve_collateral_t;
use mc_sgx_dcap_types::{QlError, Quote3};
use mc_sgx_util::ResultInto;
use std::mem;

/// The minimum size from `tee_qv_get_collateral` for the pointer to contain a
/// valid collateral.
const MIN_SGX_COLLATERAL_SIZE: u32 = mem::size_of::<sgx_ql_qve_collateral_t>() as u32;

/// A pointer to [`sgx_ql_qve_collateral_t`] that will free on drop
#[derive(Debug, PartialEq)]
struct CollateralPointer {
    collateral: *mut sgx_ql_qve_collateral_t,
}

impl AsRef<sgx_ql_qve_collateral_t> for CollateralPointer {
    fn as_ref(&self) -> &sgx_ql_qve_collateral_t {
        // SAFETY: The pointer is valid for the lifetime of this struct instance.
        // The compiler will ensure the reference doesn't outlive this struct,
        // thus the reference won't outlive the pointer.
        unsafe { &*self.collateral }
    }
}

impl Drop for CollateralPointer {
    fn drop(&mut self) {
        // SAFETY: Calling a C function is inherently unsafe. The pointer will
        // be freed if it's not null, if it happens to be null
        // `tee_qv_free_collateral` will do nothing.
        //
        // `AsRef<sgx_ql_qve_collateral_t>` is the only place that the pointer
        // may be referenced. Since this is `drop()` this struct instance is no
        // longer referenced and thus the pointer is no longer referenced.
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
    fn collateral(&self) -> Result<mc_sgx_dcap_types::Collateral, Error>;
}

impl<T: AsRef<[u8]>> Collateral for Quote3<T> {
    fn collateral(&self) -> Result<mc_sgx_dcap_types::Collateral, Error> {
        PathInitializer::ensure_initialized()?;
        LoadPolicyInitializer::ensure_initialized()?;

        let quote_slice = self.as_ref();
        let mut sgx_collateral = core::ptr::null_mut();
        let mut collateral_size = 0;

        // SAFETY: `tee_qv_get_collateral()` is a C function that is inherently unsafe.
        // The `sgx_collateral` and `collateral_size` will be checked after this
        // call to ensure they are valid.
        unsafe {
            mc_sgx_dcap_quoteverify_sys::tee_qv_get_collateral(
                quote_slice.as_ptr(),
                quote_slice.len() as u32,
                &mut sgx_collateral,
                &mut collateral_size,
            )
        }
        .into_result()?;

        // It shouldn't happen that `tee_qv_get_collateral()` returns success
        // while keeping the collateral as a null pointer, but we defend against
        // it since we don't control the C implementation.
        if sgx_collateral.is_null() {
            return Err(Error::QuoteLibrary(QlError::NoQuoteCollateralData));
        }

        // Wrap up the pointer to ensure drop will be called to free the pointer
        // if a later error occurs.
        let collateral_pointer = CollateralPointer {
            collateral: sgx_collateral as *mut _,
        };

        // The `collateral_size` is the size of the base structure plus the size
        // of all the bytes that the members point to. Thus it should always be
        // greater than `MIN_SGX_COLLATERAL_SIZE`.
        if collateral_size < MIN_SGX_COLLATERAL_SIZE {
            return Err(Error::CollateralSizeTooSmall(
                MIN_SGX_COLLATERAL_SIZE,
                collateral_size,
            ));
        }

        let collateral = mc_sgx_dcap_types::Collateral::try_from(collateral_pointer.as_ref())?;

        Ok(collateral)
    }
}
