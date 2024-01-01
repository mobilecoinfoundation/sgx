// Copyright (c) 2022-2024 The MobileCoin Foundation
//! Module used to assist unit tests that utilize the [`Sealed`] type

use core::{mem, slice};
use mc_sgx_tservice_sys_types::sgx_sealed_data_t;

// The buffer size for converting C types to bytes
// Extra trailing bytes (256) to store the _payload_
const BUFFER_SIZE: usize = mem::size_of::<sgx_sealed_data_t>() + 256;

/// Convert sealed data to bytes.
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
pub fn sealed_data_to_bytes(
    sealed_data: sgx_sealed_data_t,
    encrypted_data: &[u8],
    mac_text: Option<&[u8]>,
) -> [u8; BUFFER_SIZE] {
    let mut sealed_data = sealed_data;

    let mac_length = match mac_text {
        Some(text) => text.len() as u32,
        None => 0,
    };
    sealed_data.aes_data.payload_size = encrypted_data.len() as u32 + mac_length;

    // NB: The `plain_text_offset` is always the length of the
    // `encrypted_data`.  This is the way SGX works, it is probably to
    // accommodate 0 length encrypted data
    sealed_data.plain_text_offset = encrypted_data.len() as u32;

    // SAFETY: This is a test only function. The size of `sealed_data` is
    // used for reinterpretation of `sealed_data` into a byte slice. The
    // slice is copied from prior to the leaving of this function ensuring
    // the raw pointer is not persisted.
    #[allow(unsafe_code)]
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
