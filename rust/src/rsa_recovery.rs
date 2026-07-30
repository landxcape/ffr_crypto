use std::ffi::CStr;
use std::os::raw::c_char;

use rsa::hazmat::rsa_encrypt;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use zeroize::Zeroizing;

use crate::buffer::write_output;
use crate::status::{ERROR_INVALID_INPUT, ERROR_INVALID_KEY, ERROR_RSA_RECOVERY_FAILED};

fn decode_type_1_block(encoded: &[u8]) -> Result<Vec<u8>, ()> {
    if encoded.len() < 12 || encoded[0] != 0x00 || encoded[1] != 0x01 {
        return Err(());
    }

    let delimiter_offset = encoded[2..]
        .iter()
        .position(|byte| *byte == 0x00)
        .ok_or(())?;
    if delimiter_offset < 8 {
        return Err(());
    }

    let delimiter_index = delimiter_offset + 2;
    if !encoded[2..delimiter_index].iter().all(|byte| *byte == 0xff) {
        return Err(());
    }

    let payload_index = delimiter_index + 1;
    if payload_index >= encoded.len() {
        return Err(());
    }

    Ok(encoded[payload_index..].to_vec())
}

pub(crate) fn public_recover(public_key_pem: &str, input: &[u8]) -> Result<Vec<u8>, i32> {
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .or_else(|_| RsaPublicKey::from_pkcs1_pem(public_key_pem))
        .map_err(|_| ERROR_INVALID_KEY)?;
    let modulus_len = public_key.size();
    if input.len() != modulus_len {
        return Err(ERROR_INVALID_INPUT);
    }

    let representative = BigUint::from_bytes_be(input);
    if &representative >= public_key.n() {
        return Err(ERROR_RSA_RECOVERY_FAILED);
    }

    let recovered =
        rsa_encrypt(&public_key, &representative).map_err(|_| ERROR_RSA_RECOVERY_FAILED)?;
    let recovered_bytes = recovered.to_bytes_be();
    if recovered_bytes.len() > modulus_len {
        return Err(ERROR_RSA_RECOVERY_FAILED);
    }

    let mut encoded = Zeroizing::new(vec![0u8; modulus_len]);
    let offset = modulus_len - recovered_bytes.len();
    encoded[offset..].copy_from_slice(&recovered_bytes);
    decode_type_1_block(&encoded).map_err(|_| ERROR_RSA_RECOVERY_FAILED)
}

/// Recovers and validates a PKCS#1 v1.5 block-type-1 payload with an RSA public
/// key. This is payload recovery, not standard signature verification.
///
/// # Safety
/// `public_key_pem` must be a NUL-terminated string, `input` must be readable
/// for `input_len` bytes, and both output pointers must be writable. A successful
/// output must be released with `ffr_crypto_free_bytes` using its returned length.
#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_rsa_pkcs1v15_public_recover(
    public_key_pem: *const c_char,
    input: *const u8,
    input_len: usize,
    out_payload: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if public_key_pem.is_null() || input.is_null() || out_payload.is_null() || out_len.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let public_key_pem = match CStr::from_ptr(public_key_pem).to_str() {
        Ok(value) => value,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    let input = std::slice::from_raw_parts(input, input_len);

    match public_recover(public_key_pem, input) {
        Ok(payload) => write_output(payload, out_payload, out_len),
        Err(status) => status,
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr;

    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPublicKey;
    use rsa::pkcs8::{EncodePublicKey, LineEnding};
    use rsa::traits::PublicKeyParts;
    use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};

    use super::{decode_type_1_block, ffr_crypto_rsa_pkcs1v15_public_recover, public_recover};
    use crate::buffer::ffr_crypto_free_bytes;
    use crate::status::{ERROR_INVALID_INPUT, ERROR_INVALID_KEY, ERROR_RSA_RECOVERY_FAILED};

    fn valid_block(payload: &[u8]) -> Vec<u8> {
        let mut block = vec![0x00, 0x01];
        block.extend_from_slice(&[0xff; 8]);
        block.push(0x00);
        block.extend_from_slice(payload);
        block
    }

    fn recovery_fixture() -> (String, String, Vec<u8>, Vec<u8>, usize) {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let payload = b"generic recovery payload".to_vec();
        let transformed = private_key
            .sign(Pkcs1v15Sign::new_unprefixed(), &payload)
            .unwrap();
        let spki_pem = public_key.to_public_key_pem(LineEnding::LF).unwrap();
        let pkcs1_pem = public_key.to_pkcs1_pem(LineEnding::LF).unwrap();
        let modulus_len = public_key.size();
        (spki_pem, pkcs1_pem, payload, transformed, modulus_len)
    }

    #[test]
    fn recovers_non_empty_payload() {
        assert_eq!(
            decode_type_1_block(&valid_block(b"payload")),
            Ok(b"payload".to_vec())
        );
    }

    #[test]
    fn preserves_zero_octets_inside_payload() {
        assert_eq!(
            decode_type_1_block(&valid_block(&[0x41, 0x00, 0x42])),
            Ok(vec![0x41, 0x00, 0x42])
        );
    }

    #[test]
    fn rejects_invalid_leading_bytes() {
        let mut block = valid_block(b"payload");
        block[1] = 0x02;
        assert!(decode_type_1_block(&block).is_err());
    }

    #[test]
    fn rejects_short_padding() {
        assert!(decode_type_1_block(&[0x00, 0x01, 0xff, 0x00, 0x41]).is_err());
    }

    #[test]
    fn rejects_non_ff_padding() {
        let mut block = valid_block(b"payload");
        block[5] = 0xfe;
        assert!(decode_type_1_block(&block).is_err());
    }

    #[test]
    fn rejects_missing_delimiter() {
        assert!(decode_type_1_block(&[
            0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x41,
        ])
        .is_err());
    }

    #[test]
    fn rejects_empty_payload() {
        assert!(decode_type_1_block(&[
            0x00, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
        ])
        .is_err());
    }

    #[test]
    fn recovers_with_spki_and_pkcs1_public_keys() {
        let (spki, pkcs1, payload, transformed, _) = recovery_fixture();
        assert_eq!(public_recover(&spki, &transformed), Ok(payload.clone()));
        assert_eq!(public_recover(&pkcs1, &transformed), Ok(payload));
    }

    #[test]
    fn rejects_truncated_and_oversized_inputs() {
        let (spki, _, _, transformed, _) = recovery_fixture();
        assert_eq!(
            public_recover(&spki, &transformed[..transformed.len() - 1]),
            Err(ERROR_INVALID_INPUT)
        );

        let mut oversized = transformed;
        oversized.push(0);
        assert_eq!(public_recover(&spki, &oversized), Err(ERROR_INVALID_INPUT));
    }

    #[test]
    fn rejects_out_of_range_and_malformed_blocks_uniformly() {
        let (spki, _, _, _, modulus_len) = recovery_fixture();
        assert_eq!(
            public_recover(&spki, &vec![0xff; modulus_len]),
            Err(ERROR_RSA_RECOVERY_FAILED)
        );
        assert_eq!(
            public_recover(&spki, &vec![0x00; modulus_len]),
            Err(ERROR_RSA_RECOVERY_FAILED)
        );
    }

    #[test]
    fn rejects_invalid_key_material() {
        assert_eq!(
            public_recover("not a public key", &[0u8; 256]),
            Err(ERROR_INVALID_KEY)
        );
    }

    #[test]
    fn ffi_validates_pointers_and_transfers_recovered_bytes() {
        let (spki, _, payload, transformed, _) = recovery_fixture();
        let pem = CString::new(spki).unwrap();
        let mut output = ptr::null_mut();
        let mut output_len = 0usize;

        unsafe {
            assert_eq!(
                ffr_crypto_rsa_pkcs1v15_public_recover(
                    ptr::null(),
                    transformed.as_ptr(),
                    transformed.len(),
                    &mut output,
                    &mut output_len,
                ),
                ERROR_INVALID_INPUT
            );
            assert_eq!(
                ffr_crypto_rsa_pkcs1v15_public_recover(
                    pem.as_ptr(),
                    transformed.as_ptr(),
                    transformed.len(),
                    &mut output,
                    &mut output_len,
                ),
                crate::status::SUCCESS
            );
            assert_eq!(
                std::slice::from_raw_parts(output, output_len),
                payload.as_slice()
            );
            ffr_crypto_free_bytes(output, output_len);
        }
    }
}
