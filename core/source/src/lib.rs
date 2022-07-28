// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the linux SGX SDK

use std::path::PathBuf;
use std::process::Command;

const SOURCE_PATH: &str = "../vendored/linux-sgx";

struct Build {
}

impl Build {
    pub fn build() {
        let command = Command::new("make").current_dir(SOURCE_PATH).arg("preparation");
        Self::run_command(command);
        let command = Command::new("make").current_dir(SOURCE_PATH).arg("sdk_install_pkg");
        Self::run_command(command);
    }

    fn run_command(command: &mut Command) {
        let status = command.status();
        match status {
            Ok(status) => {
                if status.success() {
                    return
                }
                panic!("Exit code {}", status);
            }
            Err(fail) => panic!("Failed with: {}", failed),
        }
    }
}