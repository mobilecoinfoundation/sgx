// Copyright (c) 2022 The MobileCoin Foundation

//! This module provides the Certification Data type and it's logic

use crate::quote3::{le_u16, le_u32};
use crate::Quote3Error;

/// The minimum size of a byte array to contain a [`CertificationData`]
/// The 2(type) + 4(size) for QE certification data
pub(crate) const MIN_CERT_DATA_SIZE: usize = 6;

type Result<T> = core::result::Result<T, Quote3Error>;

/// The Quoting enclave certification data
///
/// Table 9 of
/// <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum CertificationData<'a> {
    /// Contains the following data:
    /// - Platform provisioning ID (PPID)
    /// - CPU security version number (CPUSVN)
    /// - Provisioning certification enclave security version number (PCESVN)
    /// - Provisioning certification enclave ID (PCEID)
    Ppid(Ppid<'a>),

    /// Contains the following data encrypted with RSA 2048:
    /// - Platform provisioning ID (PPID)
    /// - CPU security version number (CPUSVN)
    /// - Provisioning certification enclave security version number (PCESVN)
    /// - Provisioning certification enclave ID (PCEID)
    PpidEncryptedRsa2048(PpidEncryptedRsa2048<'a>),

    /// Contains the following data encrypted with RSA 3072:
    /// - Platform provisioning ID (PPID)
    /// - CPU security version number (CPUSVN)
    /// - Provisioning certification enclave security version number (PCESVN)
    /// - Provisioning certification enclave ID (PCEID)
    PpidEncryptedRsa3072(PpidEncryptedRsa3072<'a>),

    /// Contains the provisioning certification key (PCK) leaf certificate
    Pck(Pck<'a>),

    /// Contains the certificate chain for the provisioning certification key
    /// (PCK).
    PckCertificateChain(PckCertificateChain<'a>),

    /// ECDSA signature auxiliary data of an Intel SGX quote
    /// See `sgx_ql_cert_key_type_t::ECDSA_SIG_AUX_DATA`
    EcdsaSignatureAuxData(EcdsaSignatureAuxData<'a>),

    /// Platform manifest
    PlatformManifest(PlatformManifest<'a>),
}

impl<'a> TryFrom<&'a [u8]> for CertificationData<'a> {
    type Error = Quote3Error;

    fn try_from(bytes: &'a [u8]) -> Result<Self> {
        let actual = bytes.len();

        let mut required = MIN_CERT_DATA_SIZE;

        if actual < required {
            return Err(Quote3Error::InputLength { required, actual });
        }

        let (bytes, data_type) = le_u16(bytes);
        let (bytes, data_size_32) = le_u32(bytes);
        let data_size = data_size_32 as usize;

        required += data_size;
        if actual < required {
            return Err(Quote3Error::InputLength { required, actual });
        }
        let bytes = &bytes[..data_size];
        let data = match data_type {
            Ppid::KIND => CertificationData::Ppid(Ppid(bytes)),
            PpidEncryptedRsa2048::KIND => {
                CertificationData::PpidEncryptedRsa2048(PpidEncryptedRsa2048(bytes))
            }
            PpidEncryptedRsa3072::KIND => {
                CertificationData::PpidEncryptedRsa3072(PpidEncryptedRsa3072(bytes))
            }
            Pck::KIND => CertificationData::Pck(Pck(bytes)),
            PckCertificateChain::KIND => {
                CertificationData::PckCertificateChain(PckCertificateChain { data: bytes })
            }
            EcdsaSignatureAuxData::KIND => {
                CertificationData::EcdsaSignatureAuxData(EcdsaSignatureAuxData(bytes))
            }
            PlatformManifest::KIND => CertificationData::PlatformManifest(PlatformManifest(bytes)),
            x => return Err(Quote3Error::CertificationDataType(x)),
        };
        Ok(data)
    }
}

impl<'a> CertificationData<'a> {
    /// Data which makes up the certification data
    ///
    /// `Certification Data` member from Table 9 of
    /// <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>.
    pub fn raw_data(&self) -> &[u8] {
        match self {
            Self::Ppid(ppid) => ppid.0,
            Self::PpidEncryptedRsa2048(ppid_encrypted_rsa2048) => ppid_encrypted_rsa2048.0,
            Self::PpidEncryptedRsa3072(ppid_encrypted_rsa3072) => ppid_encrypted_rsa3072.0,
            Self::Pck(pck) => pck.0,
            Self::PckCertificateChain(pck_cert_chain) => pck_cert_chain.data,
            Self::EcdsaSignatureAuxData(ecdsa_signature_aux_data) => ecdsa_signature_aux_data.0,
            Self::PlatformManifest(platform_manifest) => platform_manifest.0,
        }
    }
}

trait CertificationDataKind {
    const KIND: u16;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
/// Contains the following data:
/// - Platform provisioning ID (PPID)
/// - CPU security version number (CPUSVN)
/// - Provisioning certification enclave security version number (PCESVN)
/// - Provisioning certification enclave ID (PCEID)
pub struct Ppid<'a>(&'a [u8]);

impl<'a> CertificationDataKind for Ppid<'a> {
    const KIND: u16 = 1;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
/// Contains the following data encrypted with RSA 2048:
/// - Platform provisioning ID (PPID)
/// - CPU security version number (CPUSVN)
/// - Provisioning certification enclave security version number (PCESVN)
/// - Provisioning certification enclave ID (PCEID)
pub struct PpidEncryptedRsa2048<'a>(&'a [u8]);

impl<'a> CertificationDataKind for PpidEncryptedRsa2048<'a> {
    const KIND: u16 = 2;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
/// Contains the following data encrypted with RSA 3072:
/// - Platform provisioning ID (PPID)
/// - CPU security version number (CPUSVN)
/// - Provisioning certification enclave security version number (PCESVN)
/// - Provisioning certification enclave ID (PCEID)
pub struct PpidEncryptedRsa3072<'a>(&'a [u8]);

impl<'a> CertificationDataKind for PpidEncryptedRsa3072<'a> {
    const KIND: u16 = 3;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
/// Contains the provisioning certification key (PCK) leaf certificate
pub struct Pck<'a>(&'a [u8]);

impl<'a> CertificationDataKind for Pck<'a> {
    const KIND: u16 = 4;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
/// Contains the certificate chain for the provisioning certification key
/// (PCK).
pub struct PckCertificateChain<'a> {
    data: &'a [u8],
}

impl<'a> CertificationDataKind for PckCertificateChain<'a> {
    const KIND: u16 = 5;
}

impl<'a> IntoIterator for &'a PckCertificateChain<'a> {
    type Item = &'a [u8];
    type IntoIter = PemIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        PemIterator {
            pem_data: self.data,
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
/// ECDSA signature auxiliary data of an Intel SGX quote
/// See `sgx_ql_cert_key_type_t::ECDSA_SIG_AUX_DATA`
pub struct EcdsaSignatureAuxData<'a>(&'a [u8]);

impl<'a> CertificationDataKind for EcdsaSignatureAuxData<'a> {
    const KIND: u16 = 6;
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
/// Platform manifest
pub struct PlatformManifest<'a>(&'a [u8]);

impl<'a> CertificationDataKind for PlatformManifest<'a> {
    const KIND: u16 = 7;
}

const BEGIN_PEM: &[u8] = b"-----BEGIN ";
const END_PEM: &[u8] = b"-----END ";

#[derive(Debug)]
pub struct PemIterator<'a> {
    pem_data: &'a [u8],
}

/// Iterator over each PEM in a provided buffer.
impl<'a> Iterator for PemIterator<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<&'a [u8]> {
        if self.pem_data.is_empty() {
            return None;
        }

        let mut label: &[u8] = b"";
        let mut start = None;
        let mut offset = 0;

        // The data comes across the wire and should only use "\n" and thus
        // won't be platform specific
        let lines = self.pem_data.split_inclusive(|e| *e == b'\n');
        for line in lines {
            match start {
                None => {
                    if line.starts_with(BEGIN_PEM) {
                        start = Some(offset);
                        label = &line[BEGIN_PEM.len()..];
                    }
                }
                Some(start) => {
                    if line.starts_with(END_PEM) {
                        // In the unlikely event there is an end footer exposed
                        // with a different label we walk over, just like if
                        // there happens to be a nested begin.
                        if &line[END_PEM.len()..] == label {
                            let end = offset + line.len();
                            let pem = &self.pem_data[start..end];
                            self.pem_data = &self.pem_data[end..];
                            return Some(pem);
                        }
                    }
                }
            }
            offset += line.len();
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    extern crate alloc;
    use alloc::vec::Vec;
    use yare::parameterized;

    #[test]
    fn zero_type_is_error() {
        let bytes = [0u8; MIN_CERT_DATA_SIZE];
        let error = CertificationData::try_from(bytes.as_slice()).unwrap_err();
        assert_eq!(error, Quote3Error::CertificationDataType(0));
    }

    #[test]
    fn type_eight_is_error() {
        let mut bytes = [0u8; MIN_CERT_DATA_SIZE];
        bytes[0] = 8;
        let error = CertificationData::try_from(bytes.as_slice()).unwrap_err();
        assert_eq!(error, Quote3Error::CertificationDataType(8));
    }

    #[parameterized(
    byte_value_one = {1, CertificationData::Ppid(Ppid(&[]))},
    byte_value_two = {2, CertificationData::PpidEncryptedRsa2048(PpidEncryptedRsa2048(&[]))},
    byte_value_three = {3, CertificationData::PpidEncryptedRsa3072(PpidEncryptedRsa3072(&[]))},
    byte_value_four = {4, CertificationData::Pck(Pck(&[]))},
    byte_value_five = {5, CertificationData::PckCertificateChain(PckCertificateChain{data: &[]})},
    byte_value_six = {6, CertificationData::EcdsaSignatureAuxData(EcdsaSignatureAuxData(&[]))},
    byte_value_seven = {7, CertificationData::PlatformManifest(PlatformManifest(&[]))},
    )]
    fn type_is_valid(data_type: u8, expected: CertificationData) {
        let mut bytes = [0u8; MIN_CERT_DATA_SIZE];
        bytes[0] = data_type;
        let certification_data = CertificationData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(certification_data, expected);
    }

    #[test]
    fn one_byte_certification_data() {
        let mut bytes = [8u8; MIN_CERT_DATA_SIZE + 1];

        // Little endian u16 type across 2 bytes
        bytes[0] = 2;
        bytes[1] = 0;

        // Little endian u32 size across 4 bytes
        bytes[2] = 1;
        bytes[3] = 0;
        bytes[4] = 0;
        bytes[5] = 0;

        let certification_data = CertificationData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(
            certification_data,
            CertificationData::PpidEncryptedRsa2048(PpidEncryptedRsa2048(&[8]))
        );
    }

    #[test]
    fn multiple_byte_certification_data() {
        let mut bytes = [4u8; MIN_CERT_DATA_SIZE + 30];

        // Little endian u16 type across 2 bytes
        bytes[0] = 3;
        bytes[1] = 0;

        // Little endian u32 size across 4 bytes
        bytes[2] = 7;
        bytes[3] = 0;
        bytes[4] = 0;
        bytes[5] = 0;

        let certification_data = CertificationData::try_from(bytes.as_slice()).unwrap();
        assert_eq!(
            certification_data,
            CertificationData::PpidEncryptedRsa3072(PpidEncryptedRsa3072(&[4u8; 7]))
        );
        assert_eq!(certification_data.raw_data(), [4u8; 7]);
    }

    #[test]
    fn certification_data_less_than_min() {
        let bytes = [0u8; MIN_CERT_DATA_SIZE - 1];
        assert_eq!(
            CertificationData::try_from(bytes.as_slice()),
            Err(Quote3Error::InputLength {
                actual: MIN_CERT_DATA_SIZE - 1,
                required: MIN_CERT_DATA_SIZE
            })
        );
    }

    #[test]
    fn certification_data_too_small_for_data() {
        let mut bytes = [0u8; MIN_CERT_DATA_SIZE];
        bytes[2] = 1;
        assert_eq!(
            CertificationData::try_from(bytes.as_slice()),
            Err(Quote3Error::InputLength {
                actual: MIN_CERT_DATA_SIZE,
                required: MIN_CERT_DATA_SIZE + 1
            })
        );
    }

    const LEAF_CERT: &str = "
        -----BEGIN CERTIFICATE-----
        MIIEjzCCBDSgAwIBAgIVAPtJxlxRlleZOb/spRh9U8K7AT/3MAoGCCqGSM49BAMC
        MHExIzAhBgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQK
        DBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV
        BAgMAkNBMQswCQYDVQQGEwJVUzAeFw0yMjA2MTMyMTQ2MzRaFw0yOTA2MTMyMTQ2
        MzRaMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgQ2VydGlmaWNhdGUxGjAYBgNV
        BAoMEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkG
        A1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
        j/Ee1lkGJofDX745Ks5qxqu7Mk7Mqcwkx58TCSTsabRCSvobSl/Ts8b0dltKUW3j
        qRd+SxnPEWJ+jUw+SpzwWaOCAqgwggKkMB8GA1UdIwQYMBaAFNDoqtp11/kuSReY
        PHsUZdDV8llNMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHBzOi8vYXBpLnRydXN0ZWRz
        ZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjMvcGNrY3JsP2Nh
        PXByb2Nlc3NvciZlbmNvZGluZz1kZXIwHQYDVR0OBBYEFKy9gk624HzNnDyCw7QW
        nhmVfE31MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMIIB1AYJKoZIhvhN
        AQ0BBIIBxTCCAcEwHgYKKoZIhvhNAQ0BAQQQ36FQl3ntUr3KUwbEFvmRGzCCAWQG
        CiqGSIb4TQENAQIwggFUMBAGCyqGSIb4TQENAQIBAgERMBAGCyqGSIb4TQENAQIC
        AgERMBAGCyqGSIb4TQENAQIDAgECMBAGCyqGSIb4TQENAQIEAgEEMBAGCyqGSIb4
        TQENAQIFAgEBMBEGCyqGSIb4TQENAQIGAgIAgDAQBgsqhkiG+E0BDQECBwIBBjAQ
        BgsqhkiG+E0BDQECCAIBADAQBgsqhkiG+E0BDQECCQIBADAQBgsqhkiG+E0BDQEC
        CgIBADAQBgsqhkiG+E0BDQECCwIBADAQBgsqhkiG+E0BDQECDAIBADAQBgsqhkiG
        +E0BDQECDQIBADAQBgsqhkiG+E0BDQECDgIBADAQBgsqhkiG+E0BDQECDwIBADAQ
        BgsqhkiG+E0BDQECEAIBADAQBgsqhkiG+E0BDQECEQIBCzAfBgsqhkiG+E0BDQEC
        EgQQERECBAGABgAAAAAAAAAAADAQBgoqhkiG+E0BDQEDBAIAADAUBgoqhkiG+E0B
        DQEEBAYAkG7VAAAwDwYKKoZIhvhNAQ0BBQoBADAKBggqhkjOPQQDAgNJADBGAiEA
        1XJi0ht4hw8YtC6E4rYscp9bF+7UOhVGeKePA5TW2FQCIQCIUAaewOuWOIvstZN4
        V8Zu8NFCC4vFg+cZqO6QfezEaA==
        -----END CERTIFICATE-----
        ";

    const INTERMEDIATE_CA: &str = "
        -----BEGIN CERTIFICATE-----
        MIICmDCCAj6gAwIBAgIVANDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC
        MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD
        b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw
        CQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHExIzAh
        BgNVBAMMGkludGVsIFNHWCBQQ0sgUHJvY2Vzc29yIENBMRowGAYDVQQKDBFJbnRl
        bCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNB
        MQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL9q+NMp2IOg
        tdl1bk/uWZ5+TGQm8aCi8z78fs+fKCQ3d+uDzXnVTAT2ZhDCifyIuJwvN3wNBp9i
        HBSSMJMJrBOjgbswgbgwHwYDVR0jBBgwFoAUImUM1lqdNInzg7SVUr9QGzknBqww
        UgYDVR0fBEswSTBHoEWgQ4ZBaHR0cHM6Ly9jZXJ0aWZpY2F0ZXMudHJ1c3RlZHNl
        cnZpY2VzLmludGVsLmNvbS9JbnRlbFNHWFJvb3RDQS5kZXIwHQYDVR0OBBYEFNDo
        qtp11/kuSReYPHsUZdDV8llNMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAG
        AQH/AgEAMAoGCCqGSM49BAMCA0gAMEUCIQCJgTbtVqOyZ1m3jqiAXM6QYa6r5sWS
        4y/G7y8uIJGxdwIgRqPvBSKzzQagBLQq5s5A70pdoiaRJ8z/0uDz4NgV91k=
        -----END CERTIFICATE-----
        ";

    const ROOT_CA: &str = "
        -----BEGIN CERTIFICATE-----
        MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
        aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
        cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
        BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
        A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
        aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
        AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
        1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
        uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
        MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
        ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
        Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
        KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
        AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
        -----END CERTIFICATE-----
        ";

    #[test]
    fn iterate_over_a_empty_pck_cert_chain() {
        let mut cert_data = [0u8; MIN_CERT_DATA_SIZE];
        cert_data[0] = 5;
        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let CertificationData::PckCertificateChain(cert_chain) = certification_data  else {
            panic!("expected a PckCertChain");
        };
        let cert_iter = cert_chain.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert!(certs.is_empty());
    }

    #[test]
    fn iterate_over_one_pem() {
        let raw_cert = textwrap::dedent(LEAF_CERT);
        let cert = raw_cert.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = cert.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(cert);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let CertificationData::PckCertificateChain(cert_chain) = certification_data  else {
            panic!("expected a PckCertChain");
        };
        let cert_iter = cert_chain.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert_eq!(certs, &[cert]);
    }

    #[test]
    fn iterate_over_a_cert_chain() {
        let mut cert_chain = Vec::new();
        cert_chain.push(5); // Concatenated PCK Cert Chain
        cert_chain.push(0);

        let mut size = 0;
        let pems = [LEAF_CERT, INTERMEDIATE_CA, ROOT_CA]
            .iter()
            .map(|p| textwrap::dedent(p))
            .collect::<Vec<_>>();
        let pem_bytes = pems
            .iter()
            .map(|p| p.trim_start().as_bytes())
            .collect::<Vec<_>>();
        for pem in &pem_bytes {
            size += pem.len();
            cert_chain.extend(*pem);
        }

        let size_32 = size as u32;
        let size_bytes = size_32.to_le_bytes();
        cert_chain.splice(2..2, size_bytes);

        let certification_data = CertificationData::try_from(cert_chain.as_slice()).unwrap();
        let CertificationData::PckCertificateChain(cert_chain) = certification_data  else {
            panic!("expected a PckCertChain");
        };
        let cert_iter = cert_chain.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert_eq!(certs, pem_bytes);
    }

    #[test]
    fn iterate_over_a_partial_pem_is_none() {
        let partial_pem = "
            -----BEGIN CERTIFICATE-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            ";
        let raw_pem = textwrap::dedent(partial_pem);
        let pem = raw_pem.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = pem.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(pem);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let CertificationData::PckCertificateChain(cert_chain) = certification_data  else {
            panic!("expected a PckCertChain");
        };
        let cert_iter = cert_chain.into_iter();
        assert!(cert_iter.collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn iterate_over_a_malformed_pem() {
        // The logic brings out a pem from begin to end, it's up to the decoder
        // that uses the pem to fail parsing it.
        let funky_pem = "
            -----BEGIN CERTIFICATE-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            -----BEGIN CERTIFICATE-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            -----END CERTIFICATE-----
            ";
        let raw_pem = textwrap::dedent(funky_pem);
        let pem = raw_pem.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = pem.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(pem);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let CertificationData::PckCertificateChain(cert_chain) = certification_data  else {
            panic!("expected a PckCertChain");
        };
        let cert_iter = cert_chain.into_iter();
        assert_eq!(cert_iter.collect::<Vec<_>>(), [pem]);
    }

    #[test]
    fn iterate_over_an_unmatched_nested_end() {
        // the middle end has a different label so will be treated as part of
        // the body.
        let funky_pem = "
            -----BEGIN CERTIFICATE-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            -----END SOMETHING-----
            MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
            aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
            -----END CERTIFICATE-----
            ";
        let raw_pem = textwrap::dedent(funky_pem);
        let pem = raw_pem.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = pem.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(pem);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let CertificationData::PckCertificateChain(cert_chain) = certification_data  else {
            panic!("expected a PckCertChain");
        };
        let cert_iter = cert_chain.into_iter();
        assert_eq!(cert_iter.collect::<Vec<_>>(), [pem]);
    }

    #[test]
    fn iterate_over_a_non_certificate_pem() {
        // Showing the iterator doesn't care what the pem is
        // Generated via
        // ```
        // openssl ecparam -name prime256v1 -genkey -out private-key.pem
        // openssl ec -in private-key.pem -pubout -out public-key.pem
        // ```
        let pem = "
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEusf6HZYngTI8XRXWlsQk3EwXbdd5
            2GlcHz8b0Y8b2qgyKDsKkL0j70cej1n7oMcqc+FKTVAa12QpFYSiaHJvGQ==
            -----END PUBLIC KEY-----
        ";

        let raw_key = textwrap::dedent(pem);
        let key = raw_key.trim_start().as_bytes();
        let mut cert_data = Vec::new();
        cert_data.push(5); // Concatenated PCK Cert Chain
        cert_data.push(0);
        let size = key.len() as u32;
        let size_bytes = size.to_le_bytes();
        cert_data.extend(size_bytes);
        cert_data.extend(key);

        let certification_data = CertificationData::try_from(cert_data.as_slice()).unwrap();
        let CertificationData::PckCertificateChain(cert_chain) = certification_data  else {
            panic!("expected a PckCertChain");
        };
        let cert_iter = cert_chain.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert_eq!(certs, &[key]);
    }

    #[test]
    fn ignore_contents_before_between_and_after_pems() {
        let padding_text = b"Some padding text\n";
        let mut cert_chain = Vec::new();
        cert_chain.push(5); // Concatenated PCK Cert Chain
        cert_chain.push(0);

        let mut size = 0;
        size += padding_text.len();
        cert_chain.extend(padding_text);

        let pems = [LEAF_CERT, INTERMEDIATE_CA, ROOT_CA]
            .iter()
            .map(|p| textwrap::dedent(p))
            .collect::<Vec<_>>();
        let pem_bytes = pems
            .iter()
            .map(|p| p.trim_start().as_bytes())
            .collect::<Vec<_>>();
        for pem in &pem_bytes {
            size += pem.len();
            cert_chain.extend(*pem);
            size += padding_text.len();
            cert_chain.extend(padding_text);
        }

        let size_32 = size as u32;
        let size_bytes = size_32.to_le_bytes();
        cert_chain.splice(2..2, size_bytes);

        let certification_data = CertificationData::try_from(cert_chain.as_slice()).unwrap();
        let CertificationData::PckCertificateChain(cert_chain) = certification_data  else {
            panic!("expected a PckCertChain");
        };
        let cert_iter = cert_chain.into_iter();
        let certs = cert_iter.collect::<Vec<_>>();
        assert_eq!(certs, pem_bytes);
    }
}
