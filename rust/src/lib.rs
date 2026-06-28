use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use rand::RngCore;
use rand::rngs::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey, Oaep, Pss};
use rsa::pkcs8::{EncodePublicKey, EncodePrivateKey, DecodePublicKey, DecodePrivateKey, LineEnding};
use sha2::{Sha256, Sha512};

// --- Error Codes ---
pub const SUCCESS: i32 = 0;
pub const ERROR_GENERIC: i32 = 1;
pub const ERROR_INVALID_KEY: i32 = 2;
pub const ERROR_ENCRYPTION_FAILED: i32 = 3;
pub const ERROR_DECRYPTION_FAILED: i32 = 4;
pub const ERROR_SIGNING_FAILED: i32 = 5;
pub const ERROR_VERIFICATION_FAILED: i32 = 6;
pub const ERROR_INVALID_INPUT: i32 = 7;

// --- Helper macros/functions for memory management ---

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        let _ = Vec::from_raw_parts(ptr, len, len);
    }
}

// --- Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) ---

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_random_bytes(buf: *mut u8, len: usize) -> i32 {
    if buf.is_null() || len == 0 {
        return ERROR_INVALID_INPUT;
    }
    let slice = std::slice::from_raw_parts_mut(buf, len);
    match OsRng.try_fill_bytes(slice) {
        Ok(_) => SUCCESS,
        Err(_) => ERROR_GENERIC,
    }
}

// --- RSA Keypair Generation ---

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_rsa_generate_keypair(
    key_size: u32,
    pub_pem: *mut *mut c_char,
    priv_pem: *mut *mut c_char,
) -> i32 {
    if pub_pem.is_null() || priv_pem.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let mut rng = OsRng;
    let bits = match key_size {
        2048 | 3072 | 4096 => key_size as usize,
        _ => return ERROR_INVALID_INPUT,
    };

    let private_key = match RsaPrivateKey::new(&mut rng, bits) {
        Ok(k) => k,
        Err(_) => return ERROR_GENERIC,
    };

    let public_key = RsaPublicKey::from(&private_key);

    let priv_pem_str = match private_key.to_pkcs8_pem(LineEnding::LF) {
        Ok(p) => p.to_string(),
        Err(_) => return ERROR_GENERIC,
    };

    let pub_pem_str = match public_key.to_public_key_pem(LineEnding::LF) {
        Ok(p) => p,
        Err(_) => return ERROR_GENERIC,
    };

    let priv_pem_c = match CString::new(priv_pem_str) {
        Ok(c) => c.into_raw(),
        Err(_) => return ERROR_GENERIC,
    };

    let pub_pem_c = match CString::new(pub_pem_str) {
        Ok(c) => c.into_raw(),
        Err(_) => {
            let _ = CString::from_raw(priv_pem_c);
            return ERROR_GENERIC;
        }
    };

    *priv_pem = priv_pem_c;
    *pub_pem = pub_pem_c;

    SUCCESS
}

// --- RSA-OAEP Encryption ---

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_rsa_encrypt(
    pub_key_pem: *const c_char,
    plaintext: *const u8,
    plaintext_len: usize,
    out_ciphertext: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if pub_key_pem.is_null() || plaintext.is_null() || out_ciphertext.is_null() || out_len.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let c_str = CStr::from_ptr(pub_key_pem);
    let pem_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_INPUT,
    };

    let public_key = match RsaPublicKey::from_public_key_pem(pem_str) {
        Ok(k) => k,
        Err(_) => return ERROR_INVALID_KEY,
    };

    let plain_slice = std::slice::from_raw_parts(plaintext, plaintext_len);
    let mut rng = OsRng;
    let padding = Oaep::new::<Sha256>();

    match public_key.encrypt(&mut rng, padding, plain_slice) {
        Ok(encrypted) => {
            let len = encrypted.len();
            let mut vec_boxed = encrypted.into_boxed_slice();
            *out_ciphertext = vec_boxed.as_mut_ptr();
            *out_len = len;
            std::mem::forget(vec_boxed);
            SUCCESS
        }
        Err(_) => ERROR_ENCRYPTION_FAILED,
    }
}

// --- RSA-OAEP Decryption ---

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_rsa_decrypt(
    priv_key_pem: *const c_char,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out_plaintext: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if priv_key_pem.is_null() || ciphertext.is_null() || out_plaintext.is_null() || out_len.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let c_str = CStr::from_ptr(priv_key_pem);
    let pem_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_INPUT,
    };

    let private_key = match RsaPrivateKey::from_pkcs8_pem(pem_str) {
        Ok(k) => k,
        Err(_) => return ERROR_INVALID_KEY,
    };

    let cipher_slice = std::slice::from_raw_parts(ciphertext, ciphertext_len);
    let padding = Oaep::new::<Sha256>();

    match private_key.decrypt(padding, cipher_slice) {
        Ok(decrypted) => {
            let len = decrypted.len();
            let mut vec_boxed = decrypted.into_boxed_slice();
            *out_plaintext = vec_boxed.as_mut_ptr();
            *out_len = len;
            std::mem::forget(vec_boxed);
            SUCCESS
        }
        Err(_) => ERROR_DECRYPTION_FAILED,
    }
}

// --- RSA-PSS Signing ---

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_rsa_sign(
    priv_key_pem: *const c_char,
    digest: *const u8,
    digest_len: usize,
    out_sig: *mut *mut u8,
    out_sig_len: *mut usize,
) -> i32 {
    if priv_key_pem.is_null() || digest.is_null() || out_sig.is_null() || out_sig_len.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let c_str = CStr::from_ptr(priv_key_pem);
    let pem_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_INPUT,
    };

    let private_key = match RsaPrivateKey::from_pkcs8_pem(pem_str) {
        Ok(k) => k,
        Err(_) => return ERROR_INVALID_KEY,
    };

    let digest_slice = std::slice::from_raw_parts(digest, digest_len);
    let mut rng = OsRng;
    let padding = Pss::new::<Sha256>();

    match private_key.sign_with_rng(&mut rng, padding, digest_slice) {
        Ok(signature) => {
            let len = signature.len();
            let mut vec_boxed = signature.into_boxed_slice();
            *out_sig = vec_boxed.as_mut_ptr();
            *out_sig_len = len;
            std::mem::forget(vec_boxed);
            SUCCESS
        }
        Err(_) => ERROR_SIGNING_FAILED,
    }
}

// --- RSA-PSS Verification ---

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_rsa_verify(
    pub_key_pem: *const c_char,
    digest: *const u8,
    digest_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if pub_key_pem.is_null() || digest.is_null() || sig.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let c_str = CStr::from_ptr(pub_key_pem);
    let pem_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return ERROR_INVALID_INPUT,
    };

    let public_key = match RsaPublicKey::from_public_key_pem(pem_str) {
        Ok(k) => k,
        Err(_) => return ERROR_INVALID_KEY,
    };

    let digest_slice = std::slice::from_raw_parts(digest, digest_len);
    let sig_slice = std::slice::from_raw_parts(sig, sig_len);
    let padding = Pss::new::<Sha256>();

    match public_key.verify(padding, digest_slice, sig_slice) {
        Ok(_) => SUCCESS,
        Err(_) => ERROR_VERIFICATION_FAILED,
    }
}

// --- Stateful Hashing API ---

use sha2::Digest as Sha2Digest;
use sha3::{Sha3_256, Sha3_512};
use blake3::Hasher as Blake3Hasher;

pub enum HasherContext {
    Sha256(Sha256),
    Sha512(Sha512),
    Sha3_256(Sha3_256),
    Sha3_512(Sha3_512),
    Blake3(Blake3Hasher),
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_hasher_new(alg_id: i32, out_hasher: *mut *mut HasherContext) -> i32 {
    if out_hasher.is_null() {
        return ERROR_INVALID_INPUT;
    }
    let context = match alg_id {
        0 => HasherContext::Sha256(Sha256::new()),
        1 => HasherContext::Sha512(Sha512::new()),
        2 => HasherContext::Sha3_256(Sha3_256::new()),
        3 => HasherContext::Sha3_512(Sha3_512::new()),
        4 => HasherContext::Blake3(Blake3Hasher::new()),
        _ => return ERROR_INVALID_INPUT,
    };
    *out_hasher = Box::into_raw(Box::new(context));
    SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_hasher_update(hasher: *mut HasherContext, data: *const u8, len: usize) -> i32 {
    if hasher.is_null() || (data.is_null() && len > 0) {
        return ERROR_INVALID_INPUT;
    }
    let slice = std::slice::from_raw_parts(data, len);
    let context = &mut *hasher;
    match context {
        HasherContext::Sha256(h) => h.update(slice),
        HasherContext::Sha512(h) => h.update(slice),
        HasherContext::Sha3_256(h) => h.update(slice),
        HasherContext::Sha3_512(h) => h.update(slice),
        HasherContext::Blake3(h) => {
            h.update(slice);
        }
    }
    SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_hasher_finalize(
    hasher: *mut HasherContext,
    out_digest: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if hasher.is_null() || out_digest.is_null() || out_len.is_null() {
        return ERROR_INVALID_INPUT;
    }
    let context = Box::from_raw(hasher);
    let digest: Vec<u8> = match *context {
        HasherContext::Sha256(h) => h.finalize().to_vec(),
        HasherContext::Sha512(h) => h.finalize().to_vec(),
        HasherContext::Sha3_256(h) => h.finalize().to_vec(),
        HasherContext::Sha3_512(h) => h.finalize().to_vec(),
        HasherContext::Blake3(h) => h.finalize().as_bytes().to_vec(),
    };
    
    let len = digest.len();
    let mut vec_boxed = digest.into_boxed_slice();
    *out_digest = vec_boxed.as_mut_ptr();
    *out_len = len;
    std::mem::forget(vec_boxed);
    SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_hasher_free(hasher: *mut HasherContext) {
    if !hasher.is_null() {
        let _ = Box::from_raw(hasher);
    }
}

// --- Symmetric Encryption (AES-GCM & ChaCha20-Poly1305) ---

use aes_gcm::{Aes128Gcm, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use aes_gcm::aead::{Aead, Payload, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_aes_gcm_encrypt(
    key: *const u8,
    key_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    out_ciphertext: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if key.is_null() || plaintext.is_null() || nonce.is_null() || out_ciphertext.is_null() || out_len.is_null() {
        return ERROR_INVALID_INPUT;
    }
    if nonce_len != 12 {
        return ERROR_INVALID_INPUT;
    }

    let key_slice = std::slice::from_raw_parts(key, key_len);
    let plain_slice = std::slice::from_raw_parts(plaintext, plaintext_len);
    let nonce_slice = std::slice::from_raw_parts(nonce, nonce_len);
    let nonce_ga = GenericArray::from_slice(nonce_slice);

    let aad_slice = if aad.is_null() || aad_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(aad, aad_len)
    };

    let payload = Payload {
        msg: plain_slice,
        aad: aad_slice,
    };

    let result = match key_len {
        16 => {
            let cipher = match Aes128Gcm::new_from_slice(key_slice) {
                Ok(c) => c,
                Err(_) => return ERROR_INVALID_KEY,
            };
            cipher.encrypt(nonce_ga, payload)
        }
        32 => {
            let cipher = match Aes256Gcm::new_from_slice(key_slice) {
                Ok(c) => c,
                Err(_) => return ERROR_INVALID_KEY,
            };
            cipher.encrypt(nonce_ga, payload)
        }
        _ => return ERROR_INVALID_KEY,
    };

    match result {
        Ok(ciphertext) => {
            let len = ciphertext.len();
            let mut vec_boxed = ciphertext.into_boxed_slice();
            *out_ciphertext = vec_boxed.as_mut_ptr();
            *out_len = len;
            std::mem::forget(vec_boxed);
            SUCCESS
        }
        Err(_) => ERROR_ENCRYPTION_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_aes_gcm_decrypt(
    key: *const u8,
    key_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    out_plaintext: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if key.is_null() || ciphertext.is_null() || nonce.is_null() || out_plaintext.is_null() || out_len.is_null() {
        return ERROR_INVALID_INPUT;
    }
    if nonce_len != 12 {
        return ERROR_INVALID_INPUT;
    }

    let key_slice = std::slice::from_raw_parts(key, key_len);
    let cipher_slice = std::slice::from_raw_parts(ciphertext, ciphertext_len);
    let nonce_slice = std::slice::from_raw_parts(nonce, nonce_len);
    let nonce_ga = GenericArray::from_slice(nonce_slice);

    let aad_slice = if aad.is_null() || aad_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(aad, aad_len)
    };

    let payload = Payload {
        msg: cipher_slice,
        aad: aad_slice,
    };

    let result = match key_len {
        16 => {
            let cipher = match Aes128Gcm::new_from_slice(key_slice) {
                Ok(c) => c,
                Err(_) => return ERROR_INVALID_KEY,
            };
            cipher.decrypt(nonce_ga, payload)
        }
        32 => {
            let cipher = match Aes256Gcm::new_from_slice(key_slice) {
                Ok(c) => c,
                Err(_) => return ERROR_INVALID_KEY,
            };
            cipher.decrypt(nonce_ga, payload)
        }
        _ => return ERROR_INVALID_KEY,
    };

    match result {
        Ok(plaintext) => {
            let len = plaintext.len();
            let mut vec_boxed = plaintext.into_boxed_slice();
            *out_plaintext = vec_boxed.as_mut_ptr();
            *out_len = len;
            std::mem::forget(vec_boxed);
            SUCCESS
        }
        Err(_) => ERROR_DECRYPTION_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_chacha20_poly1305_encrypt(
    key: *const u8,
    key_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    out_ciphertext: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if key.is_null() || plaintext.is_null() || nonce.is_null() || out_ciphertext.is_null() || out_len.is_null() {
        return ERROR_INVALID_INPUT;
    }
    if key_len != 32 || nonce_len != 12 {
        return ERROR_INVALID_INPUT;
    }

    let key_slice = std::slice::from_raw_parts(key, key_len);
    let plain_slice = std::slice::from_raw_parts(plaintext, plaintext_len);
    let nonce_slice = std::slice::from_raw_parts(nonce, nonce_len);
    let nonce_ga = GenericArray::from_slice(nonce_slice);

    let aad_slice = if aad.is_null() || aad_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(aad, aad_len)
    };

    let payload = Payload {
        msg: plain_slice,
        aad: aad_slice,
    };

    let cipher = match ChaCha20Poly1305::new_from_slice(key_slice) {
        Ok(c) => c,
        Err(_) => return ERROR_INVALID_KEY,
    };

    match cipher.encrypt(nonce_ga, payload) {
        Ok(ciphertext) => {
            let len = ciphertext.len();
            let mut vec_boxed = ciphertext.into_boxed_slice();
            *out_ciphertext = vec_boxed.as_mut_ptr();
            *out_len = len;
            std::mem::forget(vec_boxed);
            SUCCESS
        }
        Err(_) => ERROR_ENCRYPTION_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_chacha20_poly1305_decrypt(
    key: *const u8,
    key_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    nonce: *const u8,
    nonce_len: usize,
    aad: *const u8,
    aad_len: usize,
    out_plaintext: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if key.is_null() || ciphertext.is_null() || nonce.is_null() || out_plaintext.is_null() || out_len.is_null() {
        return ERROR_INVALID_INPUT;
    }
    if key_len != 32 || nonce_len != 12 {
        return ERROR_INVALID_INPUT;
    }

    let key_slice = std::slice::from_raw_parts(key, key_len);
    let cipher_slice = std::slice::from_raw_parts(ciphertext, ciphertext_len);
    let nonce_slice = std::slice::from_raw_parts(nonce, nonce_len);
    let nonce_ga = GenericArray::from_slice(nonce_slice);

    let aad_slice = if aad.is_null() || aad_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(aad, aad_len)
    };

    let payload = Payload {
        msg: cipher_slice,
        aad: aad_slice,
    };

    let cipher = match ChaCha20Poly1305::new_from_slice(key_slice) {
        Ok(c) => c,
        Err(_) => return ERROR_INVALID_KEY,
    };

    match cipher.decrypt(nonce_ga, payload) {
        Ok(plaintext) => {
            let len = plaintext.len();
            let mut vec_boxed = plaintext.into_boxed_slice();
            *out_plaintext = vec_boxed.as_mut_ptr();
            *out_len = len;
            std::mem::forget(vec_boxed);
            SUCCESS
        }
        Err(_) => ERROR_DECRYPTION_FAILED,
    }
}

// --- Key Derivation Functions (KDFs) ---

use pbkdf2::pbkdf2;
use hkdf::Hkdf;
use argon2::{Argon2, Algorithm as Argon2Algorithm, Version as Argon2Version, Params as Argon2Params};

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_pbkdf2(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    iterations: u32,
    out_key: *mut u8,
    out_key_len: usize,
) -> i32 {
    if password.is_null() || salt.is_null() || out_key.is_null() || out_key_len == 0 {
        return ERROR_INVALID_INPUT;
    }

    let password_slice = std::slice::from_raw_parts(password, password_len);
    let salt_slice = std::slice::from_raw_parts(salt, salt_len);
    let out_slice = std::slice::from_raw_parts_mut(out_key, out_key_len);

    match pbkdf2::<pbkdf2::hmac::Hmac<Sha256>>(password_slice, salt_slice, iterations, out_slice) {
        Ok(_) => SUCCESS,
        Err(_) => ERROR_GENERIC,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_hkdf(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out_key: *mut u8,
    out_key_len: usize,
) -> i32 {
    if ikm.is_null() || out_key.is_null() || out_key_len == 0 {
        return ERROR_INVALID_INPUT;
    }

    let ikm_slice = std::slice::from_raw_parts(ikm, ikm_len);
    
    let salt_slice = if salt.is_null() || salt_len == 0 {
        None
    } else {
        Some(std::slice::from_raw_parts(salt, salt_len))
    };

    let info_slice = if info.is_null() || info_len == 0 {
        &[]
    } else {
        std::slice::from_raw_parts(info, info_len)
    };

    let out_slice = std::slice::from_raw_parts_mut(out_key, out_key_len);

    let hk = Hkdf::<Sha256>::new(salt_slice, ikm_slice);
    match hk.expand(info_slice, out_slice) {
        Ok(_) => SUCCESS,
        Err(_) => ERROR_GENERIC,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_argon2(
    password: *const u8,
    password_len: usize,
    salt: *const u8,
    salt_len: usize,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    variant: i32,
    out_key: *mut u8,
    out_key_len: usize,
) -> i32 {
    if password.is_null() || salt.is_null() || out_key.is_null() || out_key_len == 0 {
        return ERROR_INVALID_INPUT;
    }

    let password_slice = std::slice::from_raw_parts(password, password_len);
    let salt_slice = std::slice::from_raw_parts(salt, salt_len);
    let out_slice = std::slice::from_raw_parts_mut(out_key, out_key_len);

    let alg = match variant {
        0 => Argon2Algorithm::Argon2id,
        1 => Argon2Algorithm::Argon2i,
        2 => Argon2Algorithm::Argon2d,
        _ => return ERROR_INVALID_INPUT,
    };

    let params = match Argon2Params::new(m_cost, t_cost, p_cost, Some(out_key_len)) {
        Ok(p) => p,
        Err(_) => return ERROR_INVALID_INPUT,
    };

    let argon = Argon2::new(alg, Argon2Version::V0x13, params);

    match argon.hash_password_into(password_slice, salt_slice, out_slice) {
        Ok(_) => SUCCESS,
        Err(_) => ERROR_GENERIC,
    }
}

// --- Elliptic Curve Cryptography (Ed25519 & X25519) ---

use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer as EdSigner, Verifier as EdVerifier};
use x25519_dalek::{StaticSecret, PublicKey as XPublicKey};

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_ed25519_generate_keypair(
    out_pub: *mut u8,
    out_priv: *mut u8,
) -> i32 {
    if out_pub.is_null() || out_priv.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let signing_key = SigningKey::from_bytes(&entropy);
    let verifying_key = signing_key.verifying_key();

    let out_pub_slice = std::slice::from_raw_parts_mut(out_pub, 32);
    let out_priv_slice = std::slice::from_raw_parts_mut(out_priv, 32);

    out_pub_slice.copy_from_slice(verifying_key.as_bytes());
    out_priv_slice.copy_from_slice(&signing_key.to_bytes());

    SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_ed25519_sign(
    priv_key: *const u8,
    message: *const u8,
    message_len: usize,
    out_sig: *mut u8,
) -> i32 {
    if priv_key.is_null() || message.is_null() || out_sig.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let priv_bytes = std::slice::from_raw_parts(priv_key, 32);
    let array: &[u8; 32] = match priv_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    let signing_key = SigningKey::from_bytes(array);

    let msg_slice = std::slice::from_raw_parts(message, message_len);
    let signature = signing_key.sign(msg_slice);

    let out_sig_slice = std::slice::from_raw_parts_mut(out_sig, 64);
    out_sig_slice.copy_from_slice(&signature.to_bytes());

    SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_ed25519_verify(
    pub_key: *const u8,
    message: *const u8,
    message_len: usize,
    sig: *const u8,
) -> i32 {
    if pub_key.is_null() || message.is_null() || sig.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let pub_bytes = std::slice::from_raw_parts(pub_key, 32);
    let array: &[u8; 32] = match pub_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return ERROR_INVALID_INPUT,
    };

    let verifying_key = match VerifyingKey::from_bytes(array) {
        Ok(vk) => vk,
        Err(_) => return ERROR_INVALID_KEY,
    };

    let sig_bytes = std::slice::from_raw_parts(sig, 64);
    let sig_array: &[u8; 64] = match sig_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    let signature = Signature::from_bytes(sig_array);

    let msg_slice = std::slice::from_raw_parts(message, message_len);
    match verifying_key.verify(msg_slice, &signature) {
        Ok(_) => SUCCESS,
        Err(_) => ERROR_VERIFICATION_FAILED,
    }
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_x25519_generate_keypair(
    out_pub: *mut u8,
    out_priv: *mut u8,
) -> i32 {
    if out_pub.is_null() || out_priv.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let mut rng = OsRng;
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = XPublicKey::from(&secret);

    let out_pub_slice = std::slice::from_raw_parts_mut(out_pub, 32);
    let out_priv_slice = std::slice::from_raw_parts_mut(out_priv, 32);

    out_pub_slice.copy_from_slice(public.as_bytes());
    out_priv_slice.copy_from_slice(&secret.to_bytes());

    SUCCESS
}

#[no_mangle]
pub unsafe extern "C" fn ffr_crypto_x25519_compute_shared_secret(
    priv_key: *const u8,
    peer_pub_key: *const u8,
    out_secret: *mut u8,
) -> i32 {
    if priv_key.is_null() || peer_pub_key.is_null() || out_secret.is_null() {
        return ERROR_INVALID_INPUT;
    }

    let priv_bytes = std::slice::from_raw_parts(priv_key, 32);
    let priv_array: &[u8; 32] = match priv_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    let secret = StaticSecret::from(*priv_array);

    let pub_bytes = std::slice::from_raw_parts(peer_pub_key, 32);
    let pub_array: &[u8; 32] = match pub_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => return ERROR_INVALID_INPUT,
    };
    let peer_public = XPublicKey::from(*pub_array);

    let shared_secret = secret.diffie_hellman(&peer_public);

    let out_secret_slice = std::slice::from_raw_parts_mut(out_secret, 32);
    out_secret_slice.copy_from_slice(shared_secret.as_bytes());

    SUCCESS
}




