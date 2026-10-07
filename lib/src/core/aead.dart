import 'dart:typed_data';

import '../bridge/crypto_bridge.dart';
import 'exceptions.dart';

// --- Symmetric Encryption (AES-GCM & ChaCha20-Poly1305) ---

/// Advanced Encryption Standard (AES) in Galois/Counter Mode (GCM).
class AesGcm {
  /// Encrypts the [plaintext] using AES-GCM with the specified [key] and [nonce].
  ///
  /// Key length must be either 16 bytes (AES-128) or 32 bytes (AES-256).
  /// Nonce length must be 12 bytes.
  /// Optional [aad] represents associated authenticated data.
  static Future<Uint8List> encrypt({
    required Uint8List key,
    required Uint8List plaintext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    if (key.length != 16 && key.length != 32) {
      throw InvalidKeyException('AES-GCM key length must be 16 or 32 bytes');
    }
    if (nonce.length != 12) {
      throw InvalidInputException('AES-GCM nonce length must be 12 bytes');
    }

    return await CryptoBridge.instance.aesGcmEncrypt(
      key: key,
      plaintext: plaintext,
      nonce: nonce,
      aad: aad,
    );
  }

  /// Decrypts the [ciphertext] using AES-GCM with the specified [key] and [nonce].
  ///
  /// Key length must be either 16 bytes (AES-128) or 32 bytes (AES-256).
  /// Nonce length must be 12 bytes.
  /// Optional [aad] represents associated authenticated data that was used during encryption.
  static Future<Uint8List> decrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    if (key.length != 16 && key.length != 32) {
      throw InvalidKeyException('AES-GCM key length must be 16 or 32 bytes');
    }
    if (nonce.length != 12) {
      throw InvalidInputException('AES-GCM nonce length must be 12 bytes');
    }

    return await CryptoBridge.instance.aesGcmDecrypt(
      key: key,
      ciphertext: ciphertext,
      nonce: nonce,
      aad: aad,
    );
  }
}

class ChaCha20Poly1305 {
  static Future<Uint8List> encrypt({
    required Uint8List key,
    required Uint8List plaintext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    if (key.length != 32) {
      throw InvalidKeyException(
        'ChaCha20-Poly1305 key length must be 32 bytes',
      );
    }
    if (nonce.length != 12) {
      throw InvalidInputException(
        'ChaCha20-Poly1305 nonce length must be 12 bytes',
      );
    }

    return await CryptoBridge.instance.chacha20Poly1305Encrypt(
      key: key,
      plaintext: plaintext,
      nonce: nonce,
      aad: aad,
    );
  }

  static Future<Uint8List> decrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    if (key.length != 32) {
      throw InvalidKeyException(
        'ChaCha20-Poly1305 key length must be 32 bytes',
      );
    }
    if (nonce.length != 12) {
      throw InvalidInputException(
        'ChaCha20-Poly1305 nonce length must be 12 bytes',
      );
    }

    return await CryptoBridge.instance.chacha20Poly1305Decrypt(
      key: key,
      ciphertext: ciphertext,
      nonce: nonce,
      aad: aad,
    );
  }
}
