// Copyright (c) 2022 The MobileCoin Foundation

//! Build the FFI type bindings for DCAP (Data Center Attestation Primitives)
//! quote generation
use bindgen::Builder;
use std::{env, path::PathBuf};

fn main() {
    let mut builder = Builder::default();
    builder = include_generate_if_configured(builder);
    builder = include_verify_if_configured(builder);
    let bindings = builder
        .header_contents("dcap_quote.h", "#include <sgx_ql_quote.h>")
        .blocklist_function("*")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .newtype_enum("_sgx_ql_request_policy")
        .newtype_enum("_quote3_error_t")
        .no_debug("_quote3_error_t")
        .newtype_enum("sgx_ql_path_type_t")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn include_verify_if_configured(builder: Builder) -> Builder {
    #[allow(unused_mut)]
    let mut builder = builder;
    #[cfg(feature = "verify")]
    {
        builder = builder.header_contents("dcap_verify.h", "#include <sgx_dcap_quoteverify.h>");
    }
    builder
}

fn include_generate_if_configured(builder: Builder) -> Builder {
    #[allow(unused_mut)]
    let mut builder = builder;
    #[cfg(feature = "generate")]
    {
        builder = builder.header_contents("dcap_generate.h", "#include <sgx_dcap_ql_wrapper.h>");
    }
    builder
}
