// Copyright (c) 2022 The MobileCoin Foundation

//! Builds the FFI function bindings for tservice, (trusted service) of the
//! Intel Intel SGX SDK

const SERVICE_FUNCTIONS: &[&str] = &[
    "sgx_create_report",
    "sgx_self_report",
    "sgx_get_key",
    "sgx_aligned_free",
    "sgx_aligned_malloc",
    "sgx_get_aligned_ptr",
    "sgx_verify_report",
    "sgx_verify_report2",
    "sgx_dh_init_session",
    "sgx_dh_responder_gen_msg1",
    "sgx_dh_responder_proc_msg2",
    "sgx_LAv1_initiator_proc_msg1",
    "sgx_LAv1_initiator_proc_msg3",
    "sgx_LAv2_initiator_proc_msg1",
    "sgx_LAv2_initiator_proc_msg3",
    "sgx_self_target",
    "sgx_seal_data",
    "sgx_seal_data_ex",
    "sgx_unseal_data",
    "sgx_mac_aadata",
    "sgx_mac_aadata_ex",
    "sgx_unmac_aadata",
    "sgx_calc_sealed_data_size",
    "sgx_get_add_mac_txt_len",
    "sgx_get_encrypt_txt_len",
];

fn main() {
    let include_path = mc_sgx_core_build::sgx_include_path();
    cargo_emit::rerun_if_changed!(include_path);

    let link_path = mc_sgx_core_build::sgx_library_path();
    cargo_emit::rerun_if_changed!(link_path);
    cargo_emit::rustc_link_search!(link_path);

    let sgx_suffix = mc_sgx_core_build::sgx_library_suffix();
    cargo_emit::rustc_link_lib!(&format!("static=sgx_tservice{}", sgx_suffix));

    let mut builder = mc_sgx_core_build::sgx_builder()
        .header("wrapper.h")
        .clang_arg(&format!("-I{}", include_path))
        .blocklist_type("*");

    for f in SERVICE_FUNCTIONS {
        builder = builder.allowlist_function(f);
    }

    let out_path = mc_sgx_core_build::build_output_path();
    builder
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
