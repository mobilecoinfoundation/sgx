// Copyright (c) 2018-2023 The MobileCoin Foundation

#[cfg(feature = "alloc")]
pub(crate) use alloc::vec::Vec;

/// Boilerplate macro to fill in any trait implementations required by
/// an SgxWrapperType that don't depend on the contents of the inner
/// type.
#[macro_export]
macro_rules! newtype_accessors_impls {
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

#[macro_export]
/// Newtype wrapper without a display implementation.
/// TODO: Remove once every type has a Display impl.
macro_rules! impl_newtype_no_display {
    ($($wrapper:ident, $inner:ty;)*) => {$(
        $crate::newtype_accessors_impls! {
            $wrapper, $inner;
        }
    )*}
}
/// Newtype wrapper for a primitive or struct type
#[macro_export]
macro_rules! impl_newtype {
    ($($wrapper:ident, $inner:ty;)*) => {$(
        $crate::newtype_accessors_impls! {
            $wrapper, $inner;
        }

        impl ::core::fmt::Display for $wrapper {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Debug::fmt(&self.0, f)
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

        $crate::newtype_accessors_impls! {
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

        impl Ord for $wrapper {
            fn cmp(&self, other: &$wrapper) -> core::cmp::Ordering {
                self.0.$fieldname.cmp(&other.0.$fieldname)
            }
        }

        impl PartialOrd for $wrapper {
            fn partial_cmp(&self, other: &$wrapper) -> Option<core::cmp::Ordering> {
                Some(self.0.$fieldname.cmp(&other.0.$fieldname))
            }
        }

        /*impl Iterator for $wrapper {
            fn next(&mut self) -> Option<Self::Item> {
                self.0.$fieldname.next()
            }
        }*/

        impl<'bytes> TryFrom<&'bytes [u8]> for $wrapper {
            type Error = $crate::FfiError;

            fn try_from(src: &[u8]) -> ::core::result::Result<Self, Self::Error> {
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

            fn try_from(src: $crate::macros::Vec<u8>) -> ::core::result::Result<Self, Self::Error> {
                Self::try_from(src.as_slice())
            }
        }

        impl From<[u8; $size]> for $wrapper {
            fn from($fieldname: [u8; $size]) -> Self {
                Self($inner { $fieldname })
            }
        }

        impl ::core::fmt::UpperHex for $wrapper {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                let inner: &[u8] = self.as_ref();
                mc_sgx_util::fmt_hex(inner, f)
            }
        }

        impl ::core::fmt::Display for $wrapper {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                write!(f, "{:#X}", self)
            }
        }

    )*}
}

#[cfg(test)]
mod test {
    extern crate std;

    use crate::FfiError;
    use std::format;
    use std::string::ToString;
    use yare::parameterized;

    const FIELD_SIZE: usize = 24;

    #[derive(Default, Debug, Eq, Clone, Copy, PartialEq)]
    struct Inner {
        field: [u8; FIELD_SIZE],
    }

    #[derive(Default, Debug, Eq, Clone, PartialEq)]
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

    #[test]
    fn newtype_byte_array_display() {
        let outer = Outer::from([
            0xABu8, 0x00, 0xcd, 0x12, 0xfe, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x0a,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        ]);
        assert_eq!(
            outer.to_string(),
            "0xAB00_CD12_FE01_0203_0405_0607_0809_0A0B_0C0D_0E0F_1011_1213"
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    struct StructInner {
        field: u32,
    }

    #[repr(transparent)]
    struct StructOuter(StructInner);
    impl_newtype! {
        StructOuter, StructInner;
    }

    #[repr(transparent)]
    struct PrimitiveOuter(u32);
    impl_newtype! {
        PrimitiveOuter, u32;
    }

    #[test]
    fn newtype_for_struct() {
        let inner = StructInner { field: 30 };
        let outer: StructOuter = inner.into();
        assert_eq!(outer.0, inner);
    }

    #[test]
    fn display_newtype_for_struct() {
        let inner = StructInner { field: 20 };
        let outer: StructOuter = inner.into();
        assert_eq!(outer.to_string(), "StructInner { field: 20 }");
    }

    #[test]
    fn display_newtype_for_struct_alternate() {
        let inner = StructInner { field: 20 };
        let outer: StructOuter = inner.into();
        let expected = r#"
            StructInner {
                field: 20,
            }"#;
        assert_eq!(format!("\n{outer:#}"), textwrap::dedent(expected));
    }

    #[test]
    fn display_newtype_for_primitive() {
        let inner = 42;
        let outer: PrimitiveOuter = inner.into();
        assert_eq!(outer.to_string(), "42");
    }
}
