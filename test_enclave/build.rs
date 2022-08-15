// Copyright (c) 2022 The MobileCoin Foundation
#![doc = include_str!("README.md")]

use bindgen::Builder;
use cargo_emit::rerun_if_changed;
use cc::Build;
use rand;
use rsa::{
    pkcs1::{EncodeRsaPrivateKey, LineEnding},
    BigUint, RsaPrivateKey,
};
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

/// Edger generated C files.  This is only the C files.
struct EdgerFiles {
    /// The full path to the trusted C file, <path/to/basename>_t.c
    trusted: PathBuf,

    /// The full path to the untrusted C file, <path/to/basename>_u.c
    untrusted: PathBuf,
}

const EDGER_FILE: &str = "src/enclave.edl";
const ENCLAVE_FILE: &str = "src/enclave.c";
const ENCLAVE_LINKER_SCRIPT: &str = "src/enclave.lds";
const ENCLAVE_CONFIG: &str = "src/config.xml";

fn main() {
    let root_dir = root_dir();
    let edger_files = build_enclave_definitions(root_dir.join(EDGER_FILE));

    build_enclave_binary([root_dir.join(ENCLAVE_FILE), edger_files.trusted]);
    build_untrusted_library(&edger_files.untrusted);

    let mut untrusted_header = edger_files.untrusted.clone();
    untrusted_header.set_extension("h");
    build_untrusted_bindings(untrusted_header);
}

/// The root dir of this crate. Will be the value of `CARGO_MANIFEST_DIR`
/// See https://doc.rust-lang.org/cargo/reference/environment-variables.html
fn root_dir() -> PathBuf {
    env::var("CARGO_MANIFEST_DIR")
        .expect("Missing env.CARGO_MANIFEST_DIR")
        .into()
}

/// The ld linker to use.  This has to be an ld linker as lld will fail
/// to link a working enclave
fn ld_linker() -> String {
    env::var("LD").unwrap_or_else(|_| "ld".into())
}

/// Create the C files for the enclave definitions.  This builds both the
/// trusted and the untrusted files.
///
/// # Arguments
///
/// * `edl_file` - The enclave definition file.
///
/// # Returns
/// The full path to resultant C files for the enclave definition
fn build_enclave_definitions<P: AsRef<Path>>(edl_file: P) -> EdgerFiles {
    rerun_if_changed!(edl_file
        .as_ref()
        .to_str()
        .expect("Invalid UTF-8 in edl path"));

    let bin_path = mc_sgx_core_build::sgx_bin_x64_dir().join("sgx_edger8r");
    let mut command = Command::new(bin_path);
    let out_dir = mc_sgx_core_build::build_output_dir();
    command
        .current_dir(&out_dir)
        .arg(edl_file.as_ref().as_os_str());
    let status = command.status().expect("Failed to run edger8r");
    match status.code().unwrap() {
        0 => (),
        code => panic!("edger8r exited with code {}", code),
    }

    let basename = edl_file.as_ref().file_stem().unwrap().to_str().unwrap();
    let trusted = out_dir.join(format!("{}_t.c", basename));
    let untrusted = out_dir.join(format!("{}_u.c", basename));

    EdgerFiles { trusted, untrusted }
}

/// Create enclave binary.  The binary is a shared library.
///
/// # Arguments
///
/// * `files` - The source files to include in the binary
///
/// # Returns
/// The full path to resultant binary file.  This binary will be signed and
/// ready for use in `sgx_create_enclave()`.
fn build_enclave_binary<P>(files: P) -> PathBuf
where
    P: IntoIterator,
    P: Clone,
    P::Item: AsRef<Path>,
{
    for file in files.clone() {
        rerun_if_changed!(file
            .as_ref()
            .to_str()
            .expect("Invalid UTF-8 in enclave C file"));
    }

    let include_dir = mc_sgx_core_build::sgx_include_dir();
    let include_string = format!("-I{}", include_dir.display());
    let tlibc_dir = include_dir.join("tlibc");
    let tlibc_string = format!("-I{}", tlibc_dir.display());

    // This `Build` builds a static library.  If we don't omit the
    // `cargo_metadata` then this static library will be linked into
    // the consuming crate. The enclave binary is meant to be a stand alone,
    // so we do *not* want to link into the consuming crate.
    // If one happens to link this in with the current crate, prepare for
    // memory seg faults as the trusted (enclave) implementations will
    // be directly linked in.
    Build::new()
        .files(files)
        .include(include_string)
        .include(tlibc_string)
        .cargo_metadata(false)
        .compile("enclave");

    let static_enclave = mc_sgx_core_build::build_output_dir().join("libenclave.a");
    let dynamic_enclave = build_dynamic_enclave_binary(static_enclave);
    sign_enclave_binary(dynamic_enclave)
}

/// Create a dynamic version of the enclave.  This is *unsigned*.
///
/// See https://github.com/alexcrichton/cc-rs/issues/250 for lack of dynamic
/// lib in cc crate
///
/// See https://github.com/intel/linux-sgx/blob/master/SampleCode/SampleEnclave/Makefile#L137
/// for link flags needed to link an enclave
///
/// # Arguments
///
/// * `static_enclave` - The static enclave binary
///
/// # Returns
/// The full path to resultant shared library file.
fn build_dynamic_enclave_binary<P: AsRef<Path>>(static_enclave: P) -> PathBuf {
    let mut dynamic_enclave = PathBuf::from(static_enclave.as_ref());
    dynamic_enclave.set_extension("so");
    let sgx_suffix = mc_sgx_core_build::sgx_library_suffix();
    let trts = format!("-lsgx_trts{}", sgx_suffix);
    let tservice = format!("-lsgx_tservice{}", sgx_suffix);

    let link_string = mc_sgx_core_build::sgx_library_string();
    let cve_link_string = mc_sgx_core_build::sgx_library_dir()
        .join("cve_2020_0551_load")
        .to_str()
        .expect("Invalid UTF-8 in cve linker path")
        .to_owned();

    let mut command = Command::new(ld_linker());
    command
        .arg("-o")
        .arg(
            dynamic_enclave
                .to_str()
                .expect("Invalid UTF-8 in static enclave path"),
        )
        .args(&["-z", "relro", "-z", "now", "-z", "noexecstack"])
        .arg(&format!("-L{}", cve_link_string))
        .arg(&format!("-L{}", link_string))
        .arg("--no-undefined")
        .arg("--nostdlib")
        .arg("--start-group")
        .args(&["--whole-archive", &trts, "--no-whole-archive"])
        .arg(static_enclave.as_ref().to_str().unwrap())
        .args(&["-lsgx_tstdc", "-lsgx_tcxx", "-lsgx_tcrypto", &tservice])
        .arg("--end-group")
        .arg("-Bstatic")
        .arg("-Bsymbolic")
        .arg("-pie")
        .arg("-eenclave_entry")
        .arg("--export-dynamic")
        .args(&["--defsym", "__ImageBase=0"])
        .arg("--gc-sections")
        .arg(&format!("--version-script={}", ENCLAVE_LINKER_SCRIPT));

    let status = command
        .status()
        .expect("Failed to run the linker for dynamic enclave");
    match status.code().unwrap() {
        0 => (),
        code => panic!("Linker exited with code {}", code),
    }
    dynamic_enclave
}

/// Sign the enclave binary
///
/// # Arguments
///
/// * `unsigned_enclave` - The unsigned enclave binary
///
/// # Returns
/// The full path to signed binary file.  This binary will be signed and
/// ready for use in `sgx_create_enclave()`.
fn sign_enclave_binary<P: AsRef<Path>>(unsigned_enclave: P) -> PathBuf {
    let mut signed_binary = PathBuf::from(unsigned_enclave.as_ref());
    signed_binary.set_extension("signed.so");

    let signing_key = get_signing_key();

    let bin_path = mc_sgx_core_build::sgx_bin_x64_dir().join("sgx_sign");
    let mut command = Command::new(bin_path);
    command
        .arg("sign")
        .arg("-enclave")
        .arg(unsigned_enclave.as_ref())
        .arg("-config")
        .arg(ENCLAVE_CONFIG)
        .arg("-key")
        .arg(signing_key)
        .arg("-out")
        .arg(&signed_binary);
    let status = command.status().expect("Failed to execute enclave signer");
    match status.code().unwrap() {
        0 => (),
        code => panic!("sgx_sign exited with code {}", code),
    }

    signed_binary
}

/// get the private signing key.
/// Due to the time to create a key file, this will favor returning an already
/// built signing key and only generate one as needed.
fn get_signing_key() -> PathBuf {
    let key_file = mc_sgx_core_build::build_output_dir().join("signing_key.pem");
    if !key_file.exists() {
        // The 3072 bit size and exponent of 3 are a restriction of `sgx_sign`
        let bit_size = 3072;
        let exponent = BigUint::from(3_u8);

        let mut rng = rand::thread_rng();
        let key = RsaPrivateKey::new_with_exp(&mut rng, bit_size, &exponent)
            .expect("Failed to generate private key for enclave signing.");
        key.write_pkcs1_pem_file(&key_file, LineEnding::default())
            .expect("Failed to write out private signing key for enclave signing.");
    }
    key_file
}

/// Create untrusted library.  This is meant to be used by consuming crates.
///
/// To ensure consumers correctly call out `libsgx_urts.a`, it is *not* linked
/// in here.  This is a test support library, this intentional omission is
/// partially a build test.
///
/// # Arguments
///
/// * `untrusted_file` - The untrusted C file generated from `edger8r`
///
/// # Returns
/// The full path to resultant untrusted library.
fn build_untrusted_library<P: AsRef<Path>>(untrusted_file: P) -> PathBuf {
    let include_string = mc_sgx_core_build::sgx_include_string();
    let tlibc_string = mc_sgx_core_build::sgx_include_dir()
        .join("tlibc")
        .to_str()
        .expect("Invalid UTF-8 in tlibc include dir")
        .to_owned();

    Build::new()
        .file(untrusted_file)
        .include(include_string)
        .include(tlibc_string)
        .compile("untrusted");

    let mut untrusted_object = mc_sgx_core_build::build_output_dir();
    untrusted_object.set_file_name("untrusted.a");
    untrusted_object
}

/// Create bindings to the untrusted library.
///
/// To ensure consumers correctly call out `libsgx_urts.a`, it is *not* linked
/// in here.  This is a test support library, this intentional omission is
/// partially a build test.
///
/// # Arguments
///
/// * `header` - The untrusted header file generated from `edger8r`
fn build_untrusted_bindings<P: AsRef<Path>>(header: P) {
    let bindings = Builder::default()
        .header(header.as_ref().to_str().unwrap())
        .clang_arg(mc_sgx_core_build::sgx_include_string())
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .blocklist_type("*")
        // limit to only the functions needed
        .allowlist_function("ecall_.*")
        .generate()
        .expect("Unable to generate bindings");

    bindings
        .write_to_file(mc_sgx_core_build::build_output_dir().join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
