import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffr_crypto_bindings_generated.dart' as bindings;
import '../native/status.dart';
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

    return await Isolate.run(() async {
      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      keyPtr.cast<ffi.Uint8>().asTypedList(key.length).setAll(0, key);

      final plaintextPtr = calloc<ffi.UnsignedChar>(plaintext.length);
      plaintextPtr
          .cast<ffi.Uint8>()
          .asTypedList(plaintext.length)
          .setAll(0, plaintext);

      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      noncePtr.cast<ffi.Uint8>().asTypedList(nonce.length).setAll(0, nonce);

      final aadLength = aad?.length ?? 0;
      final aadPtr = aadLength > 0
          ? calloc<ffi.UnsignedChar>(aadLength)
          : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
      if (aadLength > 0) {
        aadPtr.cast<ffi.Uint8>().asTypedList(aadLength).setAll(0, aad!);
      }

      final outCiphertextPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outLenPtr = calloc<ffi.Size>();

      try {
        final status = bindings.ffr_crypto_aes_gcm_encrypt(
          keyPtr,
          key.length,
          plaintextPtr,
          plaintext.length,
          noncePtr,
          nonce.length,
          aadPtr,
          aadLength,
          outCiphertextPtr,
          outLenPtr,
        );
        checkStatus(status, 'AES-GCM encryption');

        final resultLen = outLenPtr.value;
        final resultPtr = outCiphertextPtr.value;
        final ciphertext = Uint8List.fromList(
          resultPtr.cast<ffi.Uint8>().asTypedList(resultLen),
        );

        bindings.ffr_crypto_free_bytes(resultPtr, resultLen);
        return ciphertext;
      } finally {
        calloc.free(keyPtr);
        calloc.free(plaintextPtr);
        calloc.free(noncePtr);
        if (aadLength > 0) calloc.free(aadPtr);
        calloc.free(outCiphertextPtr);
        calloc.free(outLenPtr);
      }
    });
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

    return await Isolate.run(() async {
      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      keyPtr.cast<ffi.Uint8>().asTypedList(key.length).setAll(0, key);

      final ciphertextPtr = calloc<ffi.UnsignedChar>(ciphertext.length);
      ciphertextPtr
          .cast<ffi.Uint8>()
          .asTypedList(ciphertext.length)
          .setAll(0, ciphertext);

      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      noncePtr.cast<ffi.Uint8>().asTypedList(nonce.length).setAll(0, nonce);

      final aadLength = aad?.length ?? 0;
      final aadPtr = aadLength > 0
          ? calloc<ffi.UnsignedChar>(aadLength)
          : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
      if (aadLength > 0) {
        aadPtr.cast<ffi.Uint8>().asTypedList(aadLength).setAll(0, aad!);
      }

      final outPlaintextPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outLenPtr = calloc<ffi.Size>();

      try {
        final status = bindings.ffr_crypto_aes_gcm_decrypt(
          keyPtr,
          key.length,
          ciphertextPtr,
          ciphertext.length,
          noncePtr,
          nonce.length,
          aadPtr,
          aadLength,
          outPlaintextPtr,
          outLenPtr,
        );
        checkStatus(status, 'AES-GCM decryption');

        final resultLen = outLenPtr.value;
        final resultPtr = outPlaintextPtr.value;
        final plaintext = Uint8List.fromList(
          resultPtr.cast<ffi.Uint8>().asTypedList(resultLen),
        );

        bindings.ffr_crypto_free_bytes(resultPtr, resultLen);
        return plaintext;
      } finally {
        calloc.free(keyPtr);
        calloc.free(ciphertextPtr);
        calloc.free(noncePtr);
        if (aadLength > 0) calloc.free(aadPtr);
        calloc.free(outPlaintextPtr);
        calloc.free(outLenPtr);
      }
    });
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

    return await Isolate.run(() async {
      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      keyPtr.cast<ffi.Uint8>().asTypedList(key.length).setAll(0, key);

      final plaintextPtr = calloc<ffi.UnsignedChar>(plaintext.length);
      plaintextPtr
          .cast<ffi.Uint8>()
          .asTypedList(plaintext.length)
          .setAll(0, plaintext);

      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      noncePtr.cast<ffi.Uint8>().asTypedList(nonce.length).setAll(0, nonce);

      final aadLength = aad?.length ?? 0;
      final aadPtr = aadLength > 0
          ? calloc<ffi.UnsignedChar>(aadLength)
          : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
      if (aadLength > 0) {
        aadPtr.cast<ffi.Uint8>().asTypedList(aadLength).setAll(0, aad!);
      }

      final outCiphertextPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outLenPtr = calloc<ffi.Size>();

      try {
        final status = bindings.ffr_crypto_chacha20_poly1305_encrypt(
          keyPtr,
          key.length,
          plaintextPtr,
          plaintext.length,
          noncePtr,
          nonce.length,
          aadPtr,
          aadLength,
          outCiphertextPtr,
          outLenPtr,
        );
        checkStatus(status, 'ChaCha20-Poly1305 encryption');

        final resultLen = outLenPtr.value;
        final resultPtr = outCiphertextPtr.value;
        final ciphertext = Uint8List.fromList(
          resultPtr.cast<ffi.Uint8>().asTypedList(resultLen),
        );

        bindings.ffr_crypto_free_bytes(resultPtr, resultLen);
        return ciphertext;
      } finally {
        calloc.free(keyPtr);
        calloc.free(plaintextPtr);
        calloc.free(noncePtr);
        if (aadLength > 0) calloc.free(aadPtr);
        calloc.free(outCiphertextPtr);
        calloc.free(outLenPtr);
      }
    });
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

    return await Isolate.run(() async {
      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      keyPtr.cast<ffi.Uint8>().asTypedList(key.length).setAll(0, key);

      final ciphertextPtr = calloc<ffi.UnsignedChar>(ciphertext.length);
      ciphertextPtr
          .cast<ffi.Uint8>()
          .asTypedList(ciphertext.length)
          .setAll(0, ciphertext);

      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      noncePtr.cast<ffi.Uint8>().asTypedList(nonce.length).setAll(0, nonce);

      final aadLength = aad?.length ?? 0;
      final aadPtr = aadLength > 0
          ? calloc<ffi.UnsignedChar>(aadLength)
          : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
      if (aadLength > 0) {
        aadPtr.cast<ffi.Uint8>().asTypedList(aadLength).setAll(0, aad!);
      }

      final outPlaintextPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outLenPtr = calloc<ffi.Size>();

      try {
        final status = bindings.ffr_crypto_chacha20_poly1305_decrypt(
          keyPtr,
          key.length,
          ciphertextPtr,
          ciphertext.length,
          noncePtr,
          nonce.length,
          aadPtr,
          aadLength,
          outPlaintextPtr,
          outLenPtr,
        );
        checkStatus(status, 'ChaCha20-Poly1305 decryption');

        final resultLen = outLenPtr.value;
        final resultPtr = outPlaintextPtr.value;
        final plaintext = Uint8List.fromList(
          resultPtr.cast<ffi.Uint8>().asTypedList(resultLen),
        );

        bindings.ffr_crypto_free_bytes(resultPtr, resultLen);
        return plaintext;
      } finally {
        calloc.free(keyPtr);
        calloc.free(ciphertextPtr);
        calloc.free(noncePtr);
        if (aadLength > 0) calloc.free(aadPtr);
        calloc.free(outPlaintextPtr);
        calloc.free(outLenPtr);
      }
    });
  }
}
