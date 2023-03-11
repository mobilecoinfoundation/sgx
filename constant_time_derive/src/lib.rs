use proc_macro::TokenStream;
use quote::quote;
use syn;
use subtle::{ConstantTimeEq, Choice};


#[proc_macro_derive(ConstantTimeEq)]
pub fn constant_time_eq(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    impl_constant_time_eq(&input)
}

fn impl_constant_time_eq(ast: &syn::DeriveInput) -> TokenStream {
    let name = &ast.ident;
    let gen = quote! {
        impl ConstantTimeEq for #name {
            fn ct_eq(&self, other: &Self) -> Choice {
                let result1 = self.0.flags.ct_eq(&other.0.flags);
                let result2 = self.0.xfrm.ct_eq(&other.0.xfrm);
                return result1 & result2

            }
        }
    };
    gen.into()
}

macro_rules! constant_time_eq{
    ($a:expr, $b:expr) => {
        $a.0.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
