// Copyright (c) 2018-2022 The MobileCoin Foundation

pub(crate) use alloc::vec::Vec;

/// Boilerplate macro to fill in any trait implementations required by
/// an SgxWrapperType that don't depend on the contents of the inner
/// type.
#[macro_export]
macro_rules! new_type_accessors_impls {
    ($($wrapper:ident, $inner:ty;)*) => {$(
        impl AsMut<$inner> for $wrapper {
            fn as_mut(&mut self) -> &mut $inner {
                &mut self.0
            }
        }

        impl AsRef<$inner> for $wrapper {
            fn as_ref(&self) -> &$inner {
                &self.0
            }
        }

        impl From<$inner> for $wrapper {
            fn from(src: $inner) -> Self {
                Self(src)
            }
        }

        impl<'src> From<&'src $inner> for $wrapper {
            fn from(src: &$inner) -> Self {
                Self(src.clone())
            }
        }

        impl From<$wrapper> for $inner {
            fn from(src: $wrapper) -> $inner {
                src.0
            }
        }

    )*}
}

/// This macro provides common byte-handling operations when the type being
/// wrapped is a struct containing a single fixed-size array of bytes.
///
/// This should be called from within a private submodule.
#[macro_export]
macro_rules! impl_newtype_for_bytestruct {
    ($($wrapper:ident, $inner:ty, $fieldname:ident;)*) => {$(

        $crate::new_type_accessors_impls! {
            $wrapper, $inner;
        }

        impl AsRef<[u8]> for $wrapper {
            fn as_ref(&self) -> &[u8] {
                &(self.0).$fieldname[..]
            }
        }

        impl AsMut<[u8]> for $wrapper {
            fn as_mut(&mut self) -> &mut [u8] {
                &mut (self.0).$fieldname[..]
            }
        }

        impl<'bytes> TryFrom<&'bytes [u8]> for $wrapper {
            type Error = $crate::error::FfiError;

            fn try_from(src: &[u8]) -> core::result::Result<Self, Self::Error> {
                let mut retval = $wrapper::default();
                let size = (retval.0).$fieldname.len();
                if src.len() < size {
                    return Err($crate::error::FfiError::InvalidInputLength);
                }

                (retval.0).$fieldname[..].copy_from_slice(&src[..size]);
                Ok(retval)
            }
        }

        impl TryFrom<$crate::macros::Vec<u8>> for $wrapper {
            type Error = $crate::error::FfiError;

            fn try_from(src: $crate::macros::Vec<u8>) -> core::result::Result<Self, Self::Error> {
                Self::try_from(src.as_slice())
            }
        }

    )*}
}
