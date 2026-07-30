import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffr_crypto_bindings_generated.dart' as bindings;
import '../native/status.dart';
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

    return await Isolate.run(() async {
      final passwordPtr = calloc<ffi.UnsignedChar>(password.length);
      passwordPtr
          .cast<ffi.Uint8>()
          .asTypedList(password.length)
          .setAll(0, password);

      final saltPtr = calloc<ffi.UnsignedChar>(salt.length);
      saltPtr.cast<ffi.Uint8>().asTypedList(salt.length).setAll(0, salt);

      final outKeyPtr = calloc<ffi.UnsignedChar>(keyLength);

      try {
        final status = bindings.ffr_crypto_pbkdf2(
          passwordPtr,
          password.length,
          saltPtr,
          salt.length,
          iterations,
          outKeyPtr,
          keyLength,
        );
        checkStatus(status, 'PBKDF2 key derivation');
        return Uint8List.fromList(
          outKeyPtr.cast<ffi.Uint8>().asTypedList(keyLength),
        );
      } finally {
        calloc.free(passwordPtr);
        calloc.free(saltPtr);
        calloc.free(outKeyPtr);
      }
    });
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

    return await Isolate.run(() async {
      final ikmPtr = calloc<ffi.UnsignedChar>(ikm.length);
      ikmPtr.cast<ffi.Uint8>().asTypedList(ikm.length).setAll(0, ikm);

      final saltLength = salt.length;
      final saltPtr = saltLength > 0
          ? calloc<ffi.UnsignedChar>(saltLength)
          : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
      if (saltLength > 0) {
        saltPtr.cast<ffi.Uint8>().asTypedList(saltLength).setAll(0, salt);
      }

      final infoLength = info.length;
      final infoPtr = infoLength > 0
          ? calloc<ffi.UnsignedChar>(infoLength)
          : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
      if (infoLength > 0) {
        infoPtr.cast<ffi.Uint8>().asTypedList(infoLength).setAll(0, info);
      }

      final outKeyPtr = calloc<ffi.UnsignedChar>(keyLength);

      try {
        final status = bindings.ffr_crypto_hkdf(
          ikmPtr,
          ikm.length,
          saltPtr,
          saltLength,
          infoPtr,
          infoLength,
          outKeyPtr,
          keyLength,
        );
        checkStatus(status, 'HKDF key derivation');
        return Uint8List.fromList(
          outKeyPtr.cast<ffi.Uint8>().asTypedList(keyLength),
        );
      } finally {
        calloc.free(ikmPtr);
        if (saltLength > 0) calloc.free(saltPtr);
        if (infoLength > 0) calloc.free(infoPtr);
        calloc.free(outKeyPtr);
      }
    });
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

    return await Isolate.run(() async {
      final passwordPtr = calloc<ffi.UnsignedChar>(password.length);
      passwordPtr
          .cast<ffi.Uint8>()
          .asTypedList(password.length)
          .setAll(0, password);

      final saltPtr = calloc<ffi.UnsignedChar>(salt.length);
      saltPtr.cast<ffi.Uint8>().asTypedList(salt.length).setAll(0, salt);

      final outKeyPtr = calloc<ffi.UnsignedChar>(keyLength);

      try {
        final status = bindings.ffr_crypto_argon2(
          passwordPtr,
          password.length,
          saltPtr,
          salt.length,
          mCost,
          tCost,
          pCost,
          variant.index,
          outKeyPtr,
          keyLength,
        );
        checkStatus(status, 'Argon2 key derivation');
        return Uint8List.fromList(
          outKeyPtr.cast<ffi.Uint8>().asTypedList(keyLength),
        );
      } finally {
        calloc.free(passwordPtr);
        calloc.free(saltPtr);
        calloc.free(outKeyPtr);
      }
    });
  }
}
