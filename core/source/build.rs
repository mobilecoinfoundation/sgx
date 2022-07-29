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
    Path::new(env!("CARGO_MANIFEST_DIR")).join(SOURCE_PATH)
}

fn main(){
    let mut command = Command::new("make");
    command.current_dir(source_dir()).arg("preparation");
    run_command(command);
    let mut command = Command::new("make");
    //TODO not fond of the unlimited "-j" here, but on my machine build
    // times went from 8min down to 2min.  The unlimited "-j" can really
    // bog down the machine
    command.current_dir(source_dir()).arg("sdk_install_pkg").arg("-j");
    run_command(command);

    write_out_sgx_sdk_path();
}

fn write_out_sgx_sdk_path() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let sgx_sdk_path = source_dir().join("linux/installer/common/sdk/output/package");
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