// Copyright (c) 2022 The MobileCoin Foundation

/// Boilerplate macro to fill in any trait implementations required by
/// an SgxWrapperType that don't depend on the contents of the inner
/// type.
#[macro_export]
macro_rules! new_type_wrapper {
    ($($wrapper:ident, $inner:ty;)*) => {$(
        #[repr(transparent)]
        #[derive(Debug, Clone, Hash, PartialEq, Eq)]
        pub struct $wrapper($inner);

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
