# Quote Verification

A quote is the output of an attestation.  There are 2 types of quotes:

1. **Remote**: A remote attestation quote is for verifying that a quote came
   from a known enclave on a different machine. This quote is verified by an
   Intel enclave on the remote machine, the _Quoting Enclave_. This quote will
   be signed by this quoting enclave.
2. **Local**: A local attestation quote is for verifying that a quote came from
   another enclave on the same machine.

This document covers verifying a remote attestation quote.

Verification of a remote attestation DCAP quote is a multi-step process:

* [Verify the signature chain](#signature-chain)
* [Verify Certificate Revocation Lists (CRLs)](#revocation-lists)
* [Verify Quoting Enclave (QE)](#quoting-enclave)
* [Verify the Enclave report](#enclave-report)
* [Verify Trusted Computing Base (TCB)](#trusted-computing-base)

## Signature Chain

The signature chain is provided in the _Certification Data_ of the _QE
Certification Data_, see [Table 9][1]. The leaf of the chain is called the
Provisioning Certificate Key (PCK). The PCK is used to sign
the [quoting enclave](#quoting-enclave).

The chain includes the root CA, however since trust must first be established
the accepted root CA is hardcoded in the crate, see (TODO add a link when
available).

The signature chain is documented
in [Intel SGX PCK Certificate and Certificate Revocation List Profile Specification][2]
. The chain is a hierarchy of X.509 V3 certificates.

## Revocation Lists

The Certificate Revocation Lists (CRL) needs to be retrieved from Intel
at <https://api.portal.trustedservices.intel.com/documentation#pcs-certificate-v3>.

The CRL is documented
in [Intel SGX PCK Certificate and Certificate Revocation List Profile Specification][2]
. The CRL is an X.509 V2 CRL.

## Quoting Enclave

The Quoting Enclave(QE) is verified by a signature from the Provisioning
Certificate Key (PCK) from the [signature chain](#signature-chain).

The signature is available as the _QE Report Signature_ of the _ECDSA 256-bit
Quote Signature Data Structure_, see [Table4][1]. The signature is the result
the SHA256 message digest over the _QE Report_ of the _ECDSA 256-bit Quote
Signature Data Structure_, see [Table4][1].

## Enclave Report

The Enclave Report is verified by a signature from the Quoting Enclave.

The signing key is available as the _ECDSA Attestation Key_ from the
_ECDSA 256-bit Quote Signature Data Structure_, see [Table4][1].
> **TODO**: need to find out how to verify the integrity of this key

The signature is available as the _ISV Enclave Report Signature_ from the _ECDSA
256-bit Quote Signature Data Structure_, see [Table4][1]. The signature is the
result of the SHA256 message digest over the _Quote Header_ and _ISV Enclave
Report_ of the _High-Level Quote Structure_, see [Table2][1].

## Trusted Computing Base

> **Note**: The Trusted Computing Base (TCB) describes which security patches
> and features are available to the remotely attested enclave.

TODO figure this out.  There are currently 2 possibilities:

1. In live runs, the Provisioning Key Certificate(PCK) has 1 TCB entry available
   in the certificate extensions. The entry appears to be the highest. Is this
   enough? Will multiples be provided if there are multiples?
2. Call back to
   Intel, <https://api.trustedservices.intel.com/sgx/certification/v3/tcb?fmspc=00906ED50000>
   . This requires getting the `fmspc` out of the PCK certificate extensions.

## References

* <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
* <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf>

<!-- Repeated here and in references for ease of linking -->
[1]: https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf
[2]: https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf
