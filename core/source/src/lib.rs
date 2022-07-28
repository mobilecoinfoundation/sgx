// Copyright (c) 2022 The MobileCoin Foundation
//! Builds the linux SGX SDK

use std::process::Command;

const SOURCE_PATH: &str = "../vendored/linux-sgx";

pub struct Build {
}

impl Build {
    pub fn build() {
        let mut command = Command::new("make");
        command.current_dir(SOURCE_PATH).arg("preparation");
        Self::run_command(command);
        let mut command = Command::new("make");
        command.current_dir(SOURCE_PATH).arg("sdk_install_pkg");
        Self::run_command(command);
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
}