// Copyright (c) 2022 The MobileCoin Foundation
//! Build the linux SGX SDK

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const TAG: &str = "sgx_2.17";

fn main() {
    let build_dir = out_dir().join("linux-sgx");
    clone_sdk(&build_dir);
    build_sdk(&build_dir);
    write_out_sgx_sdk_path(&build_dir);
}

/// Return the output path for the build
fn out_dir() -> PathBuf {
    PathBuf::from(env::var("OUT_DIR").expect("Missing env.OUT_DIR"))
}

/// Clone the Intel SGX SDK source code.
///
/// Unfortunately the Intel SGX SDK does an in source build and it doesn't look
/// like there is any way to do an out of source build.  To minimize a dirty
/// git repo, we clone the SDK into the build directory instead of vendoring
/// it in as a submodule.
///
/// The internal build steps of the SGX SDK will download files so it's already
/// dependent on online inputs.
///
/// # Arguments
///
/// * `build_dir` - The directory to clone the repository to.  The repository
///   will end up being in `build_dir/repo_name`
fn clone_sdk<P: AsRef<Path>>(build_dir: &P) {
    let repo = if build_dir.as_ref().exists() {
        git2::Repository::open(build_dir).expect("Unable to open the linux SGX repository")
    } else {
        git2::Repository::clone("https://github.com/intel/linux-sgx.git", build_dir)
            .expect("Unable to clone the linux SGX repository")
    };
    repo.set_head(&format!("refs/tags/{}", TAG))
        .expect("Unable to set to the tag");
    repo.checkout_head(None)
        .expect("Unable to checkout git repo to specified HEAD");
}

/// Build the Intel SGX SDK, the `sdk_install_pkg`.
///
/// # Arguments
///
/// * `sdk_source_dir` - The directory of the SGX SDK source files to perform
///   the build on.
fn build_sdk<P: AsRef<Path>>(sdk_source_dir: &P) {
    let mut command = Command::new("make");
    command.current_dir(sdk_source_dir).arg("preparation");
    run_command(command);
    let mut command = Command::new("make");
    //TODO not fond of the unlimited "-j" here, but on my machine build
    // times went from 8min down to 2min.  The unlimited "-j" can really
    // bog down the machine
    command
        .current_dir(sdk_source_dir)
        .arg("sdk_install_pkg")
        .arg("-j");
    run_command(command);
}

/// Write out the vendored SGX SDK path to an intermediate file
/// `sgx_sdk_path.txt`
///
/// Due to the way the Cargo does builds, the main way to communicate between
/// a build script and the item being built is via files.  As such this will
/// write out the path to the build SGX SDK to a file that the library can
/// include.
///
/// # Arguments
///
/// * `sdk_source_dir` - The directory of the SGX SDK source files
fn write_out_sgx_sdk_path<P: AsRef<Path>>(sdk_build_dir: &P) {
    let sgx_sdk_path = sdk_build_dir
        .as_ref()
        .join("linux/installer/common/sdk/output/package");
    let out_dir = out_dir();
    fs::write(
        out_dir.join("sgx_sdk_path.txt"),
        sgx_sdk_path
            .to_str()
            .expect("Invalid UTF-8 in SGX SDK path"),
    )
    .expect("Failed to write SGX SDK path to file");
}

/// Run a command that is expected to always succeed and panic if it fails.
///
/// # Arguments
///
/// * `command` - The command to run
fn run_command(mut command: Command) {
    let status = command.status();
    match status {
        Ok(status) => {
            if status.success() {
                return;
            }
            panic!("Exit code {}", status);
        }
        Err(fail) => panic!("Failed with: {}", fail),
    }
}
