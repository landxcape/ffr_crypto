import 'dart:typed_data';

import '../bridge/crypto_bridge.dart';
import 'exceptions.dart';

// --- Key Derivation Functions (KDFs) ---

/// Password-Based Key Derivation Function 2 (PBKDF2).
class Pbkdf2 {
  /// Derives a key using PBKDF2-HMAC-SHA-256 with [password], [salt], and [iterations].
  static Future<Uint8List> deriveKey({
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int keyLength,
  }) async {
    if (keyLength <= 0) {
      throw InvalidInputException('Key length must be greater than zero');
    }
    if (iterations <= 0) {
      throw InvalidInputException('Iterations must be greater than zero');
    }

    return await CryptoBridge.instance.pbkdf2(
      password: password,
      salt: salt,
      iterations: iterations,
      outputLength: keyLength,
    );
  }
}

/// HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
class Hkdf {
  /// Derives a key using HKDF-SHA-256 using input keying material ([ikm]), [salt], and context-specific [info].
  static Future<Uint8List> deriveKey({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    required int keyLength,
  }) async {
    if (keyLength <= 0) {
      throw InvalidInputException('Key length must be greater than zero');
    }

    return await CryptoBridge.instance.hkdf(
      ikm: ikm,
      salt: salt,
      info: info,
      outputLength: keyLength,
    );
  }
}

/// Argon2 key derivation function variant (Argon2d, Argon2i, Argon2id).
enum Argon2Variant { id, i, d }

/// Argon2 password hashing and key derivation function.
class Argon2 {
  /// Derives a key using Argon2 with the specified cost parameters and [variant].
  static Future<Uint8List> deriveKey({
    required Uint8List password,
    required Uint8List salt,
    required int keyLength,
    int mCost = 65536,
    int tCost = 3,
    int pCost = 4,
    Argon2Variant variant = Argon2Variant.id,
  }) async {
    if (keyLength <= 0) {
      throw InvalidInputException('Key length must be greater than zero');
    }

    return await CryptoBridge.instance.argon2(
      password: password,
      salt: salt,
      mCost: mCost,
      tCost: tCost,
      pCost: pCost,
      variant: variant.index,
      outputLength: keyLength,
    );
  }
}
