// Copyright (c) 2018-2023 The MobileCoin Foundation

#[cfg(feature = "alloc")]
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
    ($($wrapper:ident, $inner:ident, $size:ident, $fieldname:ident;)*) => {$(

        $crate::new_type_accessors_impls! {
            $wrapper, $inner;
        }

        impl $wrapper {
            #[doc="Size of the internal array"]
            pub const SIZE: usize = $size;
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
            type Error = $crate::FfiError;

            fn try_from(src: &[u8]) -> core::result::Result<Self, Self::Error> {
                if src.len() < $size {
                    return Err($crate::FfiError::InvalidInputLength);
                }

                let mut retval = $wrapper::default();
                (retval.0).$fieldname[..].copy_from_slice(&src[..$size]);
                Ok(retval)
            }
        }

        #[cfg(feature="alloc")]
        impl TryFrom<$crate::macros::Vec<u8>> for $wrapper {
            type Error = $crate::FfiError;

            fn try_from(src: $crate::macros::Vec<u8>) -> core::result::Result<Self, Self::Error> {
                Self::try_from(src.as_slice())
            }
        }

        impl From<[u8; $size]> for $wrapper {
            fn from($fieldname: [u8; $size]) -> Self {
                Self($inner { $fieldname })
            }
        }

    )*}
}

#[cfg(test)]
mod test {
    use crate::FfiError;
    use yare::parameterized;

    const FIELD_SIZE: usize = 24;

    #[derive(Default, Debug, Clone, Copy, Eq, PartialEq)]
    struct Inner {
        field: [u8; FIELD_SIZE],
    }

    #[derive(Default, Debug, Clone, Copy, Eq, PartialEq)]
    #[repr(transparent)]
    struct Outer(Inner);

    impl_newtype_for_bytestruct! {
    Outer, Inner, FIELD_SIZE, field;
    }

    #[test]
    fn outer_from_inner() {
        let inner = Inner {
            field: [4u8; Outer::SIZE],
        };
        let outer: Outer = inner.into();
        assert_eq!(outer.0, inner);
    }

    #[parameterized(
    correct_size = { FIELD_SIZE, Ok(Outer::default()) },
    extra_large = { FIELD_SIZE + 1, Ok(Outer::default()) },
    too_small = { FIELD_SIZE - 1, Err(FfiError::InvalidInputLength) },
    )]
    fn try_from(size: usize, result: Result<Outer, FfiError>) {
        let buffer = [0; FIELD_SIZE * 2];
        let slice = &buffer[..size];
        assert_eq!(Outer::try_from(slice), result);

        #[cfg(feature = "alloc")]
        {
            use alloc::vec;
            let zero_vec = vec![0; size];
            assert_eq!(Outer::try_from(zero_vec), result);
        }
    }

    #[test]
    fn from_array() {
        let raw_array = [5u8; Outer::SIZE];
        let outer: Outer = raw_array.try_into().unwrap();
        assert_eq!(outer.0.field, raw_array);
    }

    #[test]
    fn as_ref() {
        let raw_array = [9u8; Outer::SIZE];
        let outer: Outer = raw_array.try_into().unwrap();
        assert_eq!(outer.as_ref(), raw_array);
    }

    #[test]
    fn as_mut() {
        let mut outer = Outer::default();
        let replacement = [11u8; Outer::SIZE];
        let mut_ref: &mut [u8] = outer.as_mut();
        mut_ref.copy_from_slice(&replacement);
        assert_eq!(outer.0.field, replacement);
    }

    #[test]
    fn default() {
        let outer = Outer::default();
        assert_eq!(outer.0.field, [0u8; Outer::SIZE]);
    }
}
