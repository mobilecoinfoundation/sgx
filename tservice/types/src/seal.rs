// Copyright (c) 2022 The MobileCoin Foundation
//! Types used for sealing and unsealing of secrets

use mc_sgx_core_types::KeyRequest;

/// AES GCM(Galois/Counter mode) Data
///
/// Wraps up a `&[u8]` since [mc-sgx-tservice-sys-types::sgx_aes_gcm_data_t] is
/// a dynamically sized type
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct AesGcmData<'a> {
    bytes: &'a [u8],
}

impl<'a> From<&'a [u8]> for AesGcmData<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> AesGcmData<'a> {
    const PAYLOAD_OFFSET: usize = 32;

    /// The size of the payload (encrypted data + mac text)
    fn payload_size(&self) -> usize {
        let size = u32::from_le_bytes(
            self.bytes[..4]
                .try_into()
                .expect("Failed to extract `payload_size`"),
        );
        size as usize
    }

    /// The GMAC tag of the payload
    pub fn gmac_tag(&self) -> [u8; 16] {
        self.bytes[16..32]
            .try_into()
            .expect("Failed to extract `payload_tag`")
    }

    /// The payload.  This includes the encrypted data and the MAC text
    pub fn payload(&self) -> &'a [u8] {
        let end = self.payload_size() + Self::PAYLOAD_OFFSET;
        self.bytes
            .get(Self::PAYLOAD_OFFSET..end)
            .expect("AesGcmData not large enough to contain the payload.")
    }
}

/// Sealed data
///
/// Wraps up a `&[u8]` since [mc-sgx-tservice-sys-types::sgx_sealed_data_t]
/// is a dynamically sized type
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct SealedData<'a> {
    bytes: &'a [u8],
}

impl<'a> SealedData<'a> {
    /// The key request used to seal the data
    pub fn key_request(&self) -> KeyRequest {
        let bytes: [u8; 512] = self.bytes[..512]
            .try_into()
            .expect("SealedData bytes aren't big enough to hold `key_request`");
        KeyRequest::from(&bytes)
    }

    // The offset within the `aes_data` for where the MAC starts.
    // None when there is no MAC data.
    fn mac_offset(&self) -> Option<usize> {
        let offset = u32::from_le_bytes(
            self.bytes[512..516]
                .try_into()
                .expect("Failed to extract `plain_text_offset` from SealedData"),
        );
        match offset {
            0 => None,
            v => Some(v as usize),
        }
    }

    /// The AES GCM data
    pub fn aes_gcm_data(&self) -> AesGcmData<'a> {
        AesGcmData::from(&self.bytes[528..])
    }

    /// The MAC text of the sealed data
    pub fn mac_text(&self) -> Option<&'a [u8]> {
        let offset = self.mac_offset();
        let payload = self.aes_gcm_data().payload();
        offset.map(|o| &payload[o..])
    }

    /// The encrypted data
    pub fn encrypted_data(&self) -> &'a [u8] {
        let offset = self.mac_offset();
        let payload = self.aes_gcm_data().payload();
        &payload[..offset.unwrap_or(payload.len())]
    }
}

impl<'a> From<&'a [u8]> for SealedData<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use core::{mem, slice};
    use mc_sgx_core_sys_types::sgx_key_request_t;
    use mc_sgx_tservice_sys_types::{sgx_aes_gcm_data_t, sgx_sealed_data_t, SGX_SEAL_TAG_SIZE};

    // The buffer size of the byte types.
    // Extra trailing bytes (256) to store the _payload_
    const BUFFER_SIZE: usize = mem::size_of::<sgx_sealed_data_t>() + 256;

    /// Converts sealed data to bytes.
    ///
    /// The returned bytes will be larger than the size of `sgx_sealed_data_t`
    /// in order to contain the `encrypted_data` and optional `mac_text`.
    /// The [`sgx_sealed_data_t.plain_text_offset`] and
    /// [`sgx_sealed_data_t.aes_data.payload_size`] will be updated to account
    /// for the provided `encrypted_data` and `mac_text`.
    ///
    /// #Arguments
    /// * `sealed_data` - The sealed data to start the buffer with.
    /// * `encrypted_data` - The encrypted part of the payload
    /// * `mac_text` - The MAC text of the payload
    #[allow(unsafe_code)]
    fn sealed_data_to_bytes(
        sealed_data: sgx_sealed_data_t,
        encrypted_data: &[u8],
        mac_text: Option<&[u8]>,
    ) -> [u8; BUFFER_SIZE] {
        let mut sealed_data = sealed_data;

        let mac_length = match mac_text {
            Some(text) => {
                sealed_data.plain_text_offset = encrypted_data.len() as u32;
                text.len() as u32
            }
            None => {
                sealed_data.plain_text_offset = 0;
                0
            }
        };
        sealed_data.aes_data.payload_size = encrypted_data.len() as u32 + mac_length;

        // SAFETY: This is a test only function. The size of `sealed_data` is
        // used for reinterpretation of `sealed_data` into a byte slice. The
        // slice is copied from prior to the leaving of this function ensuring
        // the raw pointer is not persisted.
        let alias_bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                &sealed_data as *const sgx_sealed_data_t as *const u8,
                mem::size_of::<sgx_sealed_data_t>(),
            )
        };

        let mut bytes: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
        bytes[..mem::size_of::<sgx_sealed_data_t>()].copy_from_slice(alias_bytes);

        let payload_offset = mem::size_of::<sgx_sealed_data_t>();
        let encrypted_data_end = payload_offset + encrypted_data.len();
        bytes[payload_offset..encrypted_data_end].copy_from_slice(encrypted_data);

        if let Some(text) = mac_text {
            let mac_offset = encrypted_data_end;
            let mac_end = mac_offset + text.len();
            bytes[mac_offset..mac_end].copy_from_slice(text);
        }
        bytes
    }

    fn sealed_data_1() -> sgx_sealed_data_t {
        let mut key_request = sgx_key_request_t::default();
        key_request.key_name = 1;
        sgx_sealed_data_t {
            key_request,
            plain_text_offset: 0, //overridden in [`sealed_data_to_bytes()`]
            reserved: [2u8; 12],
            aes_data: Default::default(),
        }
    }

    fn sealed_data_2() -> sgx_sealed_data_t {
        let mut key_request = sgx_key_request_t::default();
        key_request.key_name = 9;
        sgx_sealed_data_t {
            key_request,
            plain_text_offset: 0, //overridden in [`sealed_data_to_bytes()`]
            reserved: [8u8; 12],
            aes_data: Default::default(),
        }
    }

    /// Converts [`sgx_aes_gcm_data_t`] to bytes.
    ///
    /// The returned bytes will be larger than the size of
    /// [`sgx_aes_gcm_data_t`] in order to contain the `payload`.
    /// [`sgx_aes_gcm_data_t.payload_size`] will be updated to account for the
    /// provided `payload`.
    ///
    /// #Arguments
    /// * `aes_gcm_data` - The AES GCM d data to start the buffer with
    /// * `payload` - The payload to append to the `aes_gcm_data`
    #[allow(unsafe_code)]
    fn aes_gcm_data_to_bytes(
        aes_gcm_data: sgx_aes_gcm_data_t,
        payload: &[u8],
    ) -> [u8; BUFFER_SIZE] {
        let mut aes_gcm_data = aes_gcm_data;
        aes_gcm_data.payload_size = payload.len() as u32;

        // SAFETY: This is a test only function. The size of `sgx_aes_gcm_data_t`
        // is used for reinterpretation of `aes_gcm_data` into a byte slice. The
        // slice is copied from prior to the leaving of this function ensuring the
        // raw pointer is not persisted.
        let alias_bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                &aes_gcm_data as *const sgx_aes_gcm_data_t as *const u8,
                mem::size_of::<sgx_aes_gcm_data_t>(),
            )
        };

        let mut bytes: [u8; BUFFER_SIZE] = [0; BUFFER_SIZE];
        bytes[..mem::size_of::<sgx_aes_gcm_data_t>()].copy_from_slice(alias_bytes);

        let payload_offset = mem::size_of::<sgx_aes_gcm_data_t>();
        let payload_end = payload_offset + payload.len();
        bytes[payload_offset..payload_end].copy_from_slice(payload);

        bytes
    }

    fn aes_gcm_data_1() -> sgx_aes_gcm_data_t {
        sgx_aes_gcm_data_t {
            payload_size: 0, // replaced when converted to bytes
            reserved: [2u8; 12],
            payload_tag: [3u8; SGX_SEAL_TAG_SIZE],
            payload: Default::default(),
        }
    }

    fn aes_gcm_data_2() -> sgx_aes_gcm_data_t {
        sgx_aes_gcm_data_t {
            payload_size: 0, // replaced when converted to bytes
            reserved: [7u8; 12],
            payload_tag: [6u8; SGX_SEAL_TAG_SIZE],
            payload: Default::default(),
        }
    }

    #[test]
    fn sealed_data_1_from_bytes() {
        let mac = b"MAC contents";
        let encrypted_data = b"9876543";
        let bytes = sealed_data_to_bytes(sealed_data_1(), encrypted_data, Some(mac));
        let sealed_data = SealedData::from(bytes.as_slice());

        let mut key_request = sgx_key_request_t::default();
        key_request.key_name = 1;
        assert_eq!(sealed_data.key_request(), KeyRequest::from(key_request));
        assert_eq!(sealed_data.mac_text(), Some(mac.as_slice()));
        assert_eq!(sealed_data.encrypted_data(), encrypted_data.as_slice());
    }

    #[test]
    fn sealed_data_2_from_bytes() {
        let mac = b"If you ever drop your keys into a river of molten lava, let'em go...because man, they're gone! - Jack Handey";
        let encrypted_data = b"123456";
        let bytes = sealed_data_to_bytes(sealed_data_2(), encrypted_data, Some(mac));
        let sealed_data = SealedData::from(bytes.as_slice());

        let mut key_request = sgx_key_request_t::default();
        key_request.key_name = 9;
        assert_eq!(sealed_data.key_request(), KeyRequest::from(key_request));
        assert_eq!(sealed_data.mac_text(), Some(mac.as_slice()));
        assert_eq!(sealed_data.encrypted_data(), encrypted_data.as_slice());
    }

    #[test]
    fn sealed_data_no_mac_text() {
        let encrypted_data = b"123456";
        let bytes = sealed_data_to_bytes(sealed_data_2(), encrypted_data, None);
        let sealed_data = SealedData::from(bytes.as_slice());

        let mut key_request = sgx_key_request_t::default();
        key_request.key_name = 9;
        assert_eq!(sealed_data.key_request(), KeyRequest::from(key_request));
        assert_eq!(sealed_data.mac_text(), None);
        assert_eq!(sealed_data.encrypted_data(), encrypted_data.as_slice());
    }

    #[test]
    fn aes_data_1_from_bytes() {
        let payload = b"payload 1";
        let bytes = aes_gcm_data_to_bytes(aes_gcm_data_1(), payload);
        let aes_data = AesGcmData::from(bytes.as_slice());

        assert_eq!(aes_data.gmac_tag(), [3u8; SGX_SEAL_TAG_SIZE]);
        assert_eq!(aes_data.payload(), payload.as_slice());
    }

    #[test]
    fn aes_data_2_from_bytes() {
        let payload = b"a different contents";
        let bytes = aes_gcm_data_to_bytes(aes_gcm_data_2(), payload);
        let aes_data = AesGcmData::from(bytes.as_slice());

        assert_eq!(aes_data.gmac_tag(), [6u8; SGX_SEAL_TAG_SIZE]);
        assert_eq!(aes_data.payload(), payload.as_slice());
    }
}
