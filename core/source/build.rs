// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the linux SGX SDK

use std::{env, fs};
use std::path::{Path, PathBuf};
use std::process::Command;

fn out_dir() -> PathBuf {
    Path::new(&env::var("OUT_DIR").unwrap()).into()
}

fn main(){
    let build_dir = out_dir().join("linux-sgx");
    clone_sdk(&build_dir);
    build_sdk(&build_dir);
    write_out_sgx_sdk_path(&build_dir);
}

fn clone_sdk(build_dir: &PathBuf) {
    let repo = git2::Repository::clone("https://github.com/intel/linux-sgx.git", build_dir).unwrap();
    repo.set_head("refs/tags/sgx_2.17").unwrap();
    repo.checkout_head(None).unwrap();
}

fn build_sdk<P: AsRef<Path>>(sdk_source_dir: &P) {
    let mut command = Command::new("make");
    command.current_dir(sdk_source_dir).arg("preparation");
    run_command(command);
    let mut command = Command::new("make");
    //TODO not fond of the unlimited "-j" here, but on my machine build
    // times went from 8min down to 2min.  The unlimited "-j" can really
    // bog down the machine
    command.current_dir(sdk_source_dir).arg("sdk_install_pkg").arg("-j");
    run_command(command);
}

fn write_out_sgx_sdk_path<P: AsRef<Path>>(sdk_build_dir: &P) {
    let sgx_sdk_path = sdk_build_dir.as_ref().join("linux/installer/common/sdk/output/package");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("sgx_sdk_path.txt"), sgx_sdk_path.to_str().unwrap()).unwrap();
}

fn run_command(mut command: Command) {
    let status = command.status();
    match status {
        Ok(status) => {
            if status.success() {
                return
            }
            panic!("Exit code {}", status);
            }
            Err(fail) => panic!("Failed with: {}", fail),
        }
}