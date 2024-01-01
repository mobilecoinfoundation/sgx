// Copyright (c) 2022-2024 The MobileCoin Foundation

#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs, missing_debug_implementations, unsafe_code)]

mod format;
pub use format::fmt_hex;

/// A trait to add to an error type which can be constructed from an underlying
/// "status" type which contains both success and failure codes.
///
/// The goal is to be able to convert a unified status type into a `Result<T,
/// Error>` type.
///
/// # Examples
///
/// ```rust
/// use mc_sgx_util::ResultFrom;
///
/// /// An example FFI type
/// #[allow(non_camel_case_types)]
/// #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// pub struct a_status_t(u32);
///
/// impl a_status_t {
///     const SUCCESS: a_status_t = a_status_t(0);
///     const FAIL: a_status_t = a_status_t(1);
/// }
///
/// /// An example rusty enum wrapper for a_status_t
/// #[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// pub enum AnError {
///     Stuff,
///     Unknown
/// }
///
/// impl TryFrom<a_status_t> for AnError {
///     type Error = ();
///
///     fn try_from(value: a_status_t) -> Result<Self, ()> {
///         match value {
///             a_status_t::SUCCESS => Err(()),
///             a_status_t::FAIL => Ok(AnError::Stuff),
///             _ => Ok(AnError::Unknown)
///         }
///     }
/// }
///
/// // Pick up the default implementation of [`ResultFrom`]
/// impl ResultFrom<a_status_t> for AnError {}
///
/// let status = a_status_t::SUCCESS;
/// assert_eq!(Ok(()), AnError::result_from(status));
///
/// let status = a_status_t::FAIL;
/// assert_eq!(Err(AnError::Stuff), AnError::result_from(status));
/// ```
pub trait ResultFrom<ST>: TryFrom<ST> {
    /// Flips the result of a `TryFrom`.
    fn result_from(status: ST) -> Result<<Self as TryFrom<ST>>::Error, Self> {
        match Self::try_from(status) {
            Ok(err) => Err(err),
            Err(success_val) => Ok(success_val),
        }
    }
}

/// An inverse of the [`ResultFrom`] trait, which is attached to the status
/// type.
///
/// As with [`TryInto`](core::convert::TryInto), this trait is not intended to
/// be implemented manually, but instead should be added to an FFI type via
/// explicit impl block attached to it's derivative wrapper type.
///
/// ```rust,ignore
/// // Pick up the default implementation of [`ResultInto`]
/// impl ResultInto<AnError> for a_status_t {}
/// ```
///
/// That is, users should not attach this to a bindgen-generated status type,
/// they should attach [`ResultFrom`] to the intended error wrapper associated
/// with it, and they will get this for free.
pub trait ResultInto<T: TryFrom<Self>>: Sized {
    /// Flips the result of `T::TryFrom<Self>`.
    fn into_result(self) -> Result<<T as TryFrom<Self>>::Error, T> {
        match T::try_from(self) {
            Ok(err) => Err(err),
            Err(success_val) => Ok(success_val),
        }
    }
}
