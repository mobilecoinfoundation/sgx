// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the linux SGX SDK

use std::{env, fs};
use std::path::{Path, PathBuf};
use std::process::Command;
use cargo_emit::warning;

const SOURCE_PATH: &str = "vendored/linux-sgx";

pub struct Build {
}

fn source_dir() -> PathBuf {
    Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join(SOURCE_PATH)
}

fn build_dir() -> PathBuf {
    Path::new(&env::var("OUT_DIR").unwrap()).join("linux-sgx")
}

fn main(){
    let build_dir = build_dir();

    warning!("The source dir {:?} and the build dir {:?}", source_dir(), build_dir);
    fs_extra::dir::copy(source_dir(), &build_dir, &Default::default()).unwrap();
    build_sdk(&build_dir);
    write_out_sgx_sdk_path(&build_dir);
}

fn build_sdk<P: AsRef<Path>>(build_dir: &P) {
    let mut command = Command::new("make");
    command.current_dir(build_dir).arg("preparation");
    run_command(command);
    let mut command = Command::new("make");
    //TODO not fond of the unlimited "-j" here, but on my machine build
    // times went from 8min down to 2min.  The unlimited "-j" can really
    // bog down the machine
    command.current_dir(build_dir).arg("sdk_install_pkg").arg("-j");
    run_command(command);
}

fn write_out_sgx_sdk_path<P: AsRef<Path>>(build_dir: &P) {
    let sgx_sdk_path = build_dir.as_ref().join("linux/installer/common/sdk/output/package");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("sgx_sdk_path.txt"), sgx_sdk_path.to_str().unwrap()).unwrap();
}

// fn run_command(mut command: Command) {
fn run_command(command: Command) {
    warning!("Fake build: {:?}", command);
    // let status = command.status();
    // match status {
    //     Ok(status) => {
    //         if status.success() {
    //             return
    //         }
    //         panic!("Exit code {}", status);
    //         }
    //         Err(fail) => panic!("Failed with: {}", fail),
    //     }
}