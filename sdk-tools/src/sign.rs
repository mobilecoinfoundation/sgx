// Copyright (c) 2023-2025 The MobileCoin Foundation

//! Builder wrapper around SgxSign.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

/// Wrapper for the enclave signing tool (sgx_sign).
///
/// The enclave signing tool ships as part of the Intel® Software Guard
/// Extensions SDK. Signing an enclave is a process that involves producing a
/// signature structure that contains enclave properties such as the enclave
/// measurement. Once an enclave is signed in such structure, the modifications
/// to the enclave file (such as code, data, signature, and so on) can be
/// detected. The signing tool also evaluates the enclave image for potential
/// errors and warns you about potential security hazards.
///
/// See [Enclave Signing Tool Documentation](https://download.01.org/intel-sgx/sgx-linux/2.18/docs/Intel_SGX_Developer_Reference_Linux_2.18_Open_Source.pdf#%5B%7B%22num%22%3A85%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C94.5%2C206.25%2C0%5D)
/// for more details.

#[derive(Clone, Debug)]
pub struct SgxSign {
    /// The path to the sgx_sign executable.
    sgx_sign_path: PathBuf,
    /// Whether to ignore the presence of relocations in the enclave shared
    /// object.
    ignore_relocation_error: bool,
    /// Whether to ignore .init sections in the enclave.
    ignore_init_section_error: bool,
    /// Whether to re-sign a previously signed enclave (default: false)
    resign: bool,
}

impl Default for SgxSign {
    /// Create a new SGX signing utility from the current environment.
    fn default() -> Self {
        let bin_dir = mc_sgx_core_build::sgx_bin_x64_dir();

        SgxSign::from(bin_dir.join("sgx_sign"))
    }
}

impl SgxSign {
    /// Relocations are generally forbidden in the enclave shared object, this
    /// tells the `sgx_sign` utility to ignore those errors.
    #[must_use]
    pub fn allow_relocations(mut self, allow: bool) -> Self {
        self.ignore_relocation_error = allow;
        self
    }

    /// Whether or not to allow .init sections in the enclave.
    #[must_use]
    pub fn allow_init_sections(mut self, allow: bool) -> Self {
        self.ignore_init_section_error = allow;
        self
    }

    /// Whether to re-sign a previously signed enclave (default: false)
    #[must_use]
    pub fn allow_resign(mut self, allow: bool) -> Self {
        self.resign = allow;
        self
    }

    /// Generate the command to sign the given enclave object with the given
    /// private key and write the resulting enclave to the given path. Note
    /// that online signatures are inherently insecure.
    pub fn sign(
        &mut self,
        unsigned_enclave: impl AsRef<Path>,
        config_file: impl AsRef<Path>,
        private_key: impl AsRef<Path>,
        output_enclave: impl AsRef<Path>,
    ) -> Command {
        let mut cmd = Command::new(&self.sgx_sign_path);
        cmd.arg("sign")
            .arg("-enclave")
            .arg(unsigned_enclave.as_ref())
            .arg("-config")
            .arg(config_file.as_ref())
            .arg("-key")
            .arg(private_key.as_ref())
            .arg("-out")
            .arg(output_enclave.as_ref());

        if self.ignore_relocation_error {
            cmd.arg("-ignore-rel-error");
        }

        if self.ignore_init_section_error {
            cmd.arg("-ignore-init-sec-error");
        }

        if self.resign {
            cmd.arg("-resign");
        }

        cmd
    }

    /// Generate the command to create the data required for offline signing,
    /// and write it to the given output data path.
    pub fn gendata(
        &mut self,
        unsigned_enclave: impl AsRef<Path>,
        config_file: impl AsRef<Path>,
        output_datafile: impl AsRef<Path>,
    ) -> Command {
        let mut cmd = Command::new(&self.sgx_sign_path);
        cmd.arg("gendata")
            .arg("-enclave")
            .arg(unsigned_enclave.as_ref())
            .arg("-config")
            .arg(config_file.as_ref())
            .arg("-out")
            .arg(output_datafile.as_ref());

        if self.ignore_relocation_error {
            cmd.arg("-ignore-rel-error");
        }

        if self.ignore_init_section_error {
            cmd.arg("-ignore-init-sec-error");
        }

        if self.resign {
            cmd.arg("-resign");
        }

        cmd
    }

    /// Combine an unsigned enclave and signature into the output enclave, after
    /// checking the signature.
    pub fn catsig(
        &mut self,
        unsigned_enclave: impl AsRef<Path>,
        config_file: impl AsRef<Path>,
        public_key_pem: impl AsRef<Path>,
        enclave_signing_material: impl AsRef<Path>,
        signature: impl AsRef<Path>,
        output_enclave: impl AsRef<Path>,
    ) -> Command {
        let mut cmd = Command::new(&self.sgx_sign_path);
        cmd.arg("catsig")
            .arg("-enclave")
            .arg(unsigned_enclave.as_ref())
            .arg("-config")
            .arg(config_file.as_ref())
            .arg("-key")
            .arg(public_key_pem.as_ref())
            .arg("-unsigned")
            .arg(enclave_signing_material.as_ref())
            .arg("-sig")
            .arg(signature.as_ref())
            .arg("-out")
            .arg(output_enclave.as_ref());

        if self.ignore_relocation_error {
            cmd.arg("-ignore-rel-error");
        }

        if self.ignore_init_section_error {
            cmd.arg("-ignore-init-sec-error");
        }

        cmd
    }

    /// Examine a signed enclave file and dump the data
    pub fn dump(
        &mut self,
        signed_enclave: impl AsRef<Path>,
        css_file_path: impl AsRef<Path>,
        dump_file_path: impl AsRef<Path>,
    ) -> Command {
        let mut cmd = Command::new(&self.sgx_sign_path);
        cmd.arg("dump")
            .arg("-enclave")
            .arg(signed_enclave.as_ref())
            .arg("-dumpfile")
            .arg(dump_file_path.as_ref())
            .arg("-cssfile")
            .arg(css_file_path.as_ref());

        if self.ignore_relocation_error {
            cmd.arg("-ignore-rel-error");
        }

        if self.ignore_init_section_error {
            cmd.arg("-ignore-init-sec-error");
        }

        if self.resign {
            cmd.arg("-resign");
        }

        cmd
    }
}

/// Construct a new SgxSign utility around the given executable path
impl From<PathBuf> for SgxSign {
    fn from(sgx_sign_path: PathBuf) -> Self {
        Self {
            sgx_sign_path,
            ignore_relocation_error: false,
            ignore_init_section_error: false,
            resign: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_sign_command() {
        let cmd = format!(
            "{:?}",
            SgxSign::default().sign(
                "path_to_unsigned_enclave/file",
                "path_to_config/file",
                "path_to_private_key/file",
                "path_to_output_enclave/file",
            )
        );
        let expected_cmd = "\"/opt/intel/sgxsdk/bin/x64/sgx_sign\" \"sign\" \"-enclave\" \"path_to_unsigned_enclave/file\" \"-config\" \"path_to_config/file\" \"-key\" \"path_to_private_key/file\" \"-out\" \"path_to_output_enclave/file\"";

        assert_eq!(expected_cmd, cmd);
    }

    #[test]
    fn generate_gendata_command() {
        let cmd = format!(
            "{:?}",
            SgxSign::default().gendata(
                "path_to_unsigned_enclave/file",
                "path_to_config/file",
                "path_to_output_data/file",
            )
        );
        let expected_cmd = "\"/opt/intel/sgxsdk/bin/x64/sgx_sign\" \"gendata\" \"-enclave\" \"path_to_unsigned_enclave/file\" \"-config\" \"path_to_config/file\" \"-out\" \"path_to_output_data/file\"";

        assert_eq!(expected_cmd, cmd);
    }

    #[test]
    fn generate_catsig_command() {
        let cmd = format!(
            "{:?}",
            SgxSign::default().catsig(
                "path_to_unsigned_enclave/file",
                "path_to_config/file",
                "path_to_public_key_pem/file",
                "path_to_enclave_signing_material/file",
                "path_to_signature/file",
                "path_to_output_enclave/file",
            )
        );
        let expected_cmd = "\"/opt/intel/sgxsdk/bin/x64/sgx_sign\" \"catsig\" \"-enclave\" \"path_to_unsigned_enclave/file\" \"-config\" \"path_to_config/file\" \"-key\" \"path_to_public_key_pem/file\" \"-unsigned\" \"path_to_enclave_signing_material/file\" \"-sig\" \"path_to_signature/file\" \"-out\" \"path_to_output_enclave/file\"";

        assert_eq!(expected_cmd, cmd);
    }

    #[test]
    fn generate_dump_command() {
        let cmd = format!(
            "{:?}",
            SgxSign::default().dump(
                "path_to_signed_enclave/file",
                "path_to_css/file",
                "path_to_dump/file",
            )
        );
        let expected_cmd = "\"/opt/intel/sgxsdk/bin/x64/sgx_sign\" \"dump\" \"-enclave\" \"path_to_signed_enclave/file\" \"-dumpfile\" \"path_to_dump/file\" \"-cssfile\" \"path_to_css/file\"";

        assert_eq!(expected_cmd, cmd);
    }
}
