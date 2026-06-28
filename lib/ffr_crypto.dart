import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';
import 'src/ffr_crypto_bindings_generated.dart' as bindings;

// --- Exceptions ---

/// Base exception class for all cryptographic failures.
abstract class CryptoException implements Exception {
  final String message;
  CryptoException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

class GenericCryptoException extends CryptoException {
  GenericCryptoException(super.message);
}

class InvalidKeyException extends CryptoException {
  InvalidKeyException(super.message);
}

class EncryptionException extends CryptoException {
  EncryptionException(super.message);
}

class DecryptionException extends CryptoException {
  DecryptionException(super.message);
}

class SigningException extends CryptoException {
  SigningException(super.message);
}

class VerificationException extends CryptoException {
  VerificationException(super.message);
}

class InvalidInputException extends CryptoException {
  InvalidInputException(super.message);
}

void _checkStatus(int code, String action) {
  switch (code) {
    case 0:
      return;
    case 1:
      throw GenericCryptoException('$action failed (Generic Error)');
    case 2:
      throw InvalidKeyException('$action failed: Invalid key format/type');
    case 3:
      throw EncryptionException('$action failed');
    case 4:
      throw DecryptionException('$action failed');
    case 5:
      throw SigningException('$action failed');
    case 6:
      throw VerificationException('$action verification failed');
    case 7:
      throw InvalidInputException('$action failed: Invalid input arguments');
    default:
      throw GenericCryptoException('$action failed with unknown code: $code');
  }
}

// --- CSPRNG Random ---

class CryptoRandom {
  /// Generates [length] cryptographically secure random bytes.
  static Future<Uint8List> secureBytes(int length) async {
    if (length <= 0) {
      throw InvalidInputException('Length must be greater than zero');
    }

    // We can use direct synchronous run inside Isolate.run to keep UI smooth
    return await Isolate.run(() async {
      final ptr = calloc<ffi.UnsignedChar>(length);
      try {
        final status = bindings.ffr_crypto_random_bytes(ptr, length);
        _checkStatus(status, 'Random generation');
        return Uint8List.fromList(ptr.cast<ffi.Uint8>().asTypedList(length));
      } finally {
        calloc.free(ptr);
      }
    });
  }
}

// --- RSA Keys ---

abstract class RsaKey {
  final String pem;
  RsaKey(this.pem);
}

class RsaPublicKey extends RsaKey {
  RsaPublicKey(super.pem);
}

class RsaPrivateKey extends RsaKey {
  RsaPrivateKey(super.pem);
}

class RsaKeyPair {
  final RsaPublicKey publicKey;
  final RsaPrivateKey privateKey;

  RsaKeyPair({required this.publicKey, required this.privateKey});

  /// Generates a new RSA keypair.
  /// Supported key sizes: 2048, 3072, 4096
  static Future<RsaKeyPair> generate(int keySize) async {
    if (keySize != 2048 && keySize != 3072 && keySize != 4096) {
      throw InvalidInputException('Supported RSA key sizes: 2048, 3072, 4096');
    }

    return await Isolate.run(() async {
      final pubPemPtr = calloc<ffi.Pointer<ffi.Char>>();
      final privPemPtr = calloc<ffi.Pointer<ffi.Char>>();

      try {
        final status = bindings.ffr_crypto_rsa_generate_keypair(
          keySize,
          pubPemPtr,
          privPemPtr,
        );
        _checkStatus(status, 'RSA key generation');

        final pubStr = pubPemPtr.value.cast<Utf8>().toDartString();
        final privStr = privPemPtr.value.cast<Utf8>().toDartString();

        // Free Rust-allocated PEM strings
        bindings.ffr_crypto_free_string(pubPemPtr.value);
        bindings.ffr_crypto_free_string(privPemPtr.value);

        return RsaKeyPair(
          publicKey: RsaPublicKey(pubStr),
          privateKey: RsaPrivateKey(privStr),
        );
      } finally {
        calloc.free(pubPemPtr);
        calloc.free(privPemPtr);
      }
    });
  }
}

// --- RSA Engine ---

class Rsa {
  /// Encrypts [plaintext] using RSA-OAEP with SHA-256 padding.
  static Future<Uint8List> encrypt(
    RsaPublicKey publicKey,
    Uint8List plaintext,
  ) async {
    return await Isolate.run(() async {
      final pubKeyPtr = publicKey.pem.toNativeUtf8();
      final plaintextPtr = calloc<ffi.UnsignedChar>(plaintext.length);
      plaintextPtr
          .cast<ffi.Uint8>()
          .asTypedList(plaintext.length)
          .setAll(0, plaintext);

      final outCiphertextPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outLenPtr = calloc<ffi.Size>();

      try {
        final status = bindings.ffr_crypto_rsa_encrypt(
          pubKeyPtr.cast<ffi.Char>(),
          plaintextPtr,
          plaintext.length,
          outCiphertextPtr,
          outLenPtr,
        );
        _checkStatus(status, 'RSA encryption');

        final resultLen = outLenPtr.value;
        final resultPtr = outCiphertextPtr.value;
        final resultBytes = Uint8List.fromList(
          resultPtr.cast<ffi.Uint8>().asTypedList(resultLen),
        );

        // Free Rust-allocated bytes
        bindings.ffr_crypto_free_bytes(resultPtr, resultLen);

        return resultBytes;
      } finally {
        calloc.free(pubKeyPtr);
        calloc.free(plaintextPtr);
        calloc.free(outCiphertextPtr);
        calloc.free(outLenPtr);
      }
    });
  }

  /// Decrypts [ciphertext] using RSA-OAEP with SHA-256 padding.
  static Future<Uint8List> decrypt(
    RsaPrivateKey privateKey,
    Uint8List ciphertext,
  ) async {
    return await Isolate.run(() async {
      final privKeyPtr = privateKey.pem.toNativeUtf8();
      final ciphertextPtr = calloc<ffi.UnsignedChar>(ciphertext.length);
      ciphertextPtr
          .cast<ffi.Uint8>()
          .asTypedList(ciphertext.length)
          .setAll(0, ciphertext);

      final outPlaintextPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outLenPtr = calloc<ffi.Size>();

      try {
        final status = bindings.ffr_crypto_rsa_decrypt(
          privKeyPtr.cast<ffi.Char>(),
          ciphertextPtr,
          ciphertext.length,
          outPlaintextPtr,
          outLenPtr,
        );
        _checkStatus(status, 'RSA decryption');

        final resultLen = outLenPtr.value;
        final resultPtr = outPlaintextPtr.value;
        final resultBytes = Uint8List.fromList(
          resultPtr.cast<ffi.Uint8>().asTypedList(resultLen),
        );

        // Free Rust-allocated bytes
        bindings.ffr_crypto_free_bytes(resultPtr, resultLen);

        return resultBytes;
      } finally {
        calloc.free(privKeyPtr);
        calloc.free(ciphertextPtr);
        calloc.free(outPlaintextPtr);
        calloc.free(outLenPtr);
      }
    });
  }

  /// Signs the SHA-256 [digest] using RSA-PSS.
  static Future<Uint8List> sign(
    RsaPrivateKey privateKey,
    Uint8List digest,
  ) async {
    return await Isolate.run(() async {
      final privKeyPtr = privateKey.pem.toNativeUtf8();
      final digestPtr = calloc<ffi.UnsignedChar>(digest.length);
      digestPtr.cast<ffi.Uint8>().asTypedList(digest.length).setAll(0, digest);

      final outSigPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outSigLenPtr = calloc<ffi.Size>();

      try {
        final status = bindings.ffr_crypto_rsa_sign(
          privKeyPtr.cast<ffi.Char>(),
          digestPtr,
          digest.length,
          outSigPtr,
          outSigLenPtr,
        );
        _checkStatus(status, 'RSA signing');

        final resultLen = outSigLenPtr.value;
        final resultPtr = outSigPtr.value;
        final resultBytes = Uint8List.fromList(
          resultPtr.cast<ffi.Uint8>().asTypedList(resultLen),
        );

        // Free Rust-allocated bytes
        bindings.ffr_crypto_free_bytes(resultPtr, resultLen);

        return resultBytes;
      } finally {
        calloc.free(privKeyPtr);
        calloc.free(digestPtr);
        calloc.free(outSigPtr);
        calloc.free(outSigLenPtr);
      }
    });
  }

  /// Verifies the RSA-PSS signature [signature] against the SHA-256 [digest].
  static Future<bool> verify(
    RsaPublicKey publicKey,
    Uint8List digest,
    Uint8List signature,
  ) async {
    return await Isolate.run(() async {
      final pubKeyPtr = publicKey.pem.toNativeUtf8();
      final digestPtr = calloc<ffi.UnsignedChar>(digest.length);
      digestPtr.cast<ffi.Uint8>().asTypedList(digest.length).setAll(0, digest);

      final signaturePtr = calloc<ffi.UnsignedChar>(signature.length);
      signaturePtr
          .cast<ffi.Uint8>()
          .asTypedList(signature.length)
          .setAll(0, signature);

      try {
        final status = bindings.ffr_crypto_rsa_verify(
          pubKeyPtr.cast<ffi.Char>(),
          digestPtr,
          digest.length,
          signaturePtr,
          signature.length,
        );

        if (status == 0) return true;
        if (status == 6) return false;

        _checkStatus(status, 'RSA verification');
        return false;
      } finally {
        calloc.free(pubKeyPtr);
        calloc.free(digestPtr);
        calloc.free(signaturePtr);
      }
    });
  }
}

// --- Hashing ---

enum HashAlgorithm { sha256, sha512, sha3_256, sha3_512, blake3 }

class CryptoHasher {
  final HashAlgorithm algorithm;
  ffi.Pointer<bindings.HasherContext> _context;
  bool _isFinalized = false;

  CryptoHasher._(this.algorithm, this._context);

  static Future<CryptoHasher> create(HashAlgorithm algorithm) async {
    final contextAddr = await Isolate.run(() async {
      final outPtr = calloc<ffi.Pointer<bindings.HasherContext>>();
      try {
        final status = bindings.ffr_crypto_hasher_new(algorithm.index, outPtr);
        _checkStatus(status, 'Hasher initialization');
        return outPtr.value.address;
      } finally {
        calloc.free(outPtr);
      }
    });
    return CryptoHasher._(algorithm, ffi.Pointer.fromAddress(contextAddr));
  }

  Future<void> update(Uint8List data) async {
    if (_isFinalized) {
      throw GenericCryptoException('Hasher is already finalized');
    }
    if (_context.address == 0) {
      throw GenericCryptoException('Hasher is freed');
    }

    final contextAddress = _context.address;
    await Isolate.run(() async {
      final dataPtr = calloc<ffi.UnsignedChar>(data.length);
      dataPtr.cast<ffi.Uint8>().asTypedList(data.length).setAll(0, data);
      try {
        final status = bindings.ffr_crypto_hasher_update(
          ffi.Pointer.fromAddress(contextAddress),
          dataPtr,
          data.length,
        );
        _checkStatus(status, 'Hasher update');
      } finally {
        calloc.free(dataPtr);
      }
    });
  }

  Future<Uint8List> finalize() async {
    if (_isFinalized) {
      throw GenericCryptoException('Hasher is already finalized');
    }
    if (_context.address == 0) {
      throw GenericCryptoException('Hasher is freed');
    }

    _isFinalized = true;
    final contextAddress = _context.address;

    final digest = await Isolate.run(() async {
      final outDigestPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outLenPtr = calloc<ffi.Size>();
      try {
        final status = bindings.ffr_crypto_hasher_finalize(
          ffi.Pointer.fromAddress(contextAddress),
          outDigestPtr,
          outLenPtr,
        );
        _checkStatus(status, 'Hasher finalization');

        final resultLen = outLenPtr.value;
        final resultPtr = outDigestPtr.value;
        final bytes = Uint8List.fromList(
          resultPtr.cast<ffi.Uint8>().asTypedList(resultLen),
        );

        // Free Rust-allocated bytes
        bindings.ffr_crypto_free_bytes(resultPtr, resultLen);

        return bytes;
      } finally {
        calloc.free(outDigestPtr);
        calloc.free(outLenPtr);
      }
    });

    _context = ffi.Pointer.fromAddress(0);
    return digest;
  }

  void free() {
    if (!_isFinalized && _context.address != 0) {
      bindings.ffr_crypto_hasher_free(_context);
      _context = ffi.Pointer.fromAddress(0);
    }
  }
}

class CryptoHash {
  /// One-shot hash helper.
  static Future<Uint8List> hash(HashAlgorithm algorithm, Uint8List data) async {
    final hasher = await CryptoHasher.create(algorithm);
    try {
      await hasher.update(data);
      return await hasher.finalize();
    } catch (e) {
      hasher.free();
      rethrow;
    }
  }

  /// Hash helper that streams chunks of a Dart Stream.
  static Future<Uint8List> hashStream(
    HashAlgorithm algorithm,
    Stream<List<int>> stream,
  ) async {
    final hasher = await CryptoHasher.create(algorithm);
    try {
      await for (final chunk in stream) {
        await hasher.update(Uint8List.fromList(chunk));
      }
      return await hasher.finalize();
    } catch (e) {
      hasher.free();
      rethrow;
    }
  }
}

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
        _checkStatus(status, 'AES-GCM encryption');

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
        _checkStatus(status, 'AES-GCM decryption');

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
        _checkStatus(status, 'ChaCha20-Poly1305 encryption');

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
        _checkStatus(status, 'ChaCha20-Poly1305 decryption');

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
        _checkStatus(status, 'PBKDF2 key derivation');
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
        _checkStatus(status, 'HKDF key derivation');
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
        _checkStatus(status, 'Argon2 key derivation');
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

// --- Elliptic Curve Cryptography (Ed25519 & X25519) ---

class Ed25519KeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;
  Ed25519KeyPair(this.publicKey, this.privateKey);
}

class Ed25519 {
  static Future<Ed25519KeyPair> generateKeyPair() async {
    return await Isolate.run(() async {
      final pubPtr = calloc<ffi.UnsignedChar>(32);
      final privPtr = calloc<ffi.UnsignedChar>(32);
      try {
        final status = bindings.ffr_crypto_ed25519_generate_keypair(
          pubPtr,
          privPtr,
        );
        _checkStatus(status, 'Ed25519 key generation');

        final pubBytes = Uint8List.fromList(
          pubPtr.cast<ffi.Uint8>().asTypedList(32),
        );
        final privBytes = Uint8List.fromList(
          privPtr.cast<ffi.Uint8>().asTypedList(32),
        );
        return Ed25519KeyPair(pubBytes, privBytes);
      } finally {
        calloc.free(pubPtr);
        calloc.free(privPtr);
      }
    });
  }

  static Future<Uint8List> sign({
    required Uint8List privateKey,
    required Uint8List message,
  }) async {
    if (privateKey.length != 32) {
      throw InvalidKeyException('Ed25519 private key must be 32 bytes');
    }

    return await Isolate.run(() async {
      final privPtr = calloc<ffi.UnsignedChar>(32);
      privPtr.cast<ffi.Uint8>().asTypedList(32).setAll(0, privateKey);

      final msgPtr = calloc<ffi.UnsignedChar>(message.length);
      msgPtr.cast<ffi.Uint8>().asTypedList(message.length).setAll(0, message);

      final sigPtr = calloc<ffi.UnsignedChar>(64);

      try {
        final status = bindings.ffr_crypto_ed25519_sign(
          privPtr,
          msgPtr,
          message.length,
          sigPtr,
        );
        _checkStatus(status, 'Ed25519 signing');
        return Uint8List.fromList(sigPtr.cast<ffi.Uint8>().asTypedList(64));
      } finally {
        calloc.free(privPtr);
        calloc.free(msgPtr);
        calloc.free(sigPtr);
      }
    });
  }

  static Future<bool> verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) async {
    if (publicKey.length != 32) {
      throw InvalidKeyException('Ed25519 public key must be 32 bytes');
    }
    if (signature.length != 64) {
      throw InvalidInputException('Ed25519 signature must be 64 bytes');
    }

    return await Isolate.run(() async {
      final pubPtr = calloc<ffi.UnsignedChar>(32);
      pubPtr.cast<ffi.Uint8>().asTypedList(32).setAll(0, publicKey);

      final msgPtr = calloc<ffi.UnsignedChar>(message.length);
      msgPtr.cast<ffi.Uint8>().asTypedList(message.length).setAll(0, message);

      final sigPtr = calloc<ffi.UnsignedChar>(64);
      sigPtr.cast<ffi.Uint8>().asTypedList(64).setAll(0, signature);

      try {
        final status = bindings.ffr_crypto_ed25519_verify(
          pubPtr,
          msgPtr,
          message.length,
          sigPtr,
        );
        if (status == 0) return true;
        if (status == 6) return false;
        _checkStatus(status, 'Ed25519 verification');
        return false;
      } finally {
        calloc.free(pubPtr);
        calloc.free(msgPtr);
        calloc.free(sigPtr);
      }
    });
  }
}

class X25519KeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;
  X25519KeyPair(this.publicKey, this.privateKey);
}

class X25519 {
  static Future<X25519KeyPair> generateKeyPair() async {
    return await Isolate.run(() async {
      final pubPtr = calloc<ffi.UnsignedChar>(32);
      final privPtr = calloc<ffi.UnsignedChar>(32);
      try {
        final status = bindings.ffr_crypto_x25519_generate_keypair(
          pubPtr,
          privPtr,
        );
        _checkStatus(status, 'X25519 key generation');

        final pubBytes = Uint8List.fromList(
          pubPtr.cast<ffi.Uint8>().asTypedList(32),
        );
        final privBytes = Uint8List.fromList(
          privPtr.cast<ffi.Uint8>().asTypedList(32),
        );
        return X25519KeyPair(pubBytes, privBytes);
      } finally {
        calloc.free(pubPtr);
        calloc.free(privPtr);
      }
    });
  }

  static Future<Uint8List> computeSharedSecret({
    required Uint8List privateKey,
    required Uint8List peerPublicKey,
  }) async {
    if (privateKey.length != 32) {
      throw InvalidKeyException('X25519 private key must be 32 bytes');
    }
    if (peerPublicKey.length != 32) {
      throw InvalidKeyException('X25519 peer public key must be 32 bytes');
    }

    return await Isolate.run(() async {
      final privPtr = calloc<ffi.UnsignedChar>(32);
      privPtr.cast<ffi.Uint8>().asTypedList(32).setAll(0, privateKey);

      final pubPtr = calloc<ffi.UnsignedChar>(32);
      pubPtr.cast<ffi.Uint8>().asTypedList(32).setAll(0, peerPublicKey);

      final secretPtr = calloc<ffi.UnsignedChar>(32);

      try {
        final status = bindings.ffr_crypto_x25519_compute_shared_secret(
          privPtr,
          pubPtr,
          secretPtr,
        );
        _checkStatus(status, 'X25519 secret agreement');
        return Uint8List.fromList(secretPtr.cast<ffi.Uint8>().asTypedList(32));
      } finally {
        calloc.free(privPtr);
        calloc.free(pubPtr);
        calloc.free(secretPtr);
      }
    });
  }
}

class HybridEncryption {
  /// Encrypts a [plaintext] message for a recipient identified by their X25519 [recipientPublicKey].
  /// Returns a packaged payload containing: Ephemeral Public Key (32 bytes) + Ciphertext + Tag (16 bytes).
  static Future<Uint8List> encrypt({
    required Uint8List recipientPublicKey,
    required Uint8List plaintext,
  }) async {
    if (recipientPublicKey.length != 32) {
      throw InvalidKeyException('Recipient public key must be 32 bytes');
    }

    // 1. Generate ephemeral key pair
    final ephemeral = await X25519.generateKeyPair();

    // 2. Compute shared secret
    final sharedSecret = await X25519.computeSharedSecret(
      privateKey: ephemeral.privateKey,
      peerPublicKey: recipientPublicKey,
    );

    // 3. Derive symmetric key (32 bytes) and nonce (12 bytes) using HKDF
    final derived = await Hkdf.deriveKey(
      ikm: sharedSecret,
      salt: Uint8List(0),
      info: ephemeral.publicKey,
      keyLength: 44, // 32 bytes key + 12 bytes nonce
    );

    final symKey = derived.sublist(0, 32);
    final nonce = derived.sublist(32, 44);

    // 4. Encrypt using ChaCha20-Poly1305
    final ciphertext = await ChaCha20Poly1305.encrypt(
      key: symKey,
      plaintext: plaintext,
      nonce: nonce,
    );

    // 5. Package output: Ephemeral Pubkey (32 bytes) + Ciphertext
    final payload = BytesBuilder();
    payload.add(ephemeral.publicKey);
    payload.add(ciphertext);
    return payload.toBytes();
  }

  /// Decrypts a packaged hybrid encryption payload using the recipient's X25519 [recipientPrivateKey].
  static Future<Uint8List> decrypt({
    required Uint8List recipientPrivateKey,
    required Uint8List payload,
  }) async {
    if (recipientPrivateKey.length != 32) {
      throw InvalidKeyException('Recipient private key must be 32 bytes');
    }
    if (payload.length < 48) {
      // 32 bytes (pubkey) + 16 bytes (tag minimum)
      throw InvalidInputException('Invalid hybrid encryption payload size');
    }

    // 1. Extract ephemeral pubkey and ciphertext
    final ephemeralPublicKey = payload.sublist(0, 32);
    final ciphertext = payload.sublist(32);

    // 2. Compute shared secret
    final sharedSecret = await X25519.computeSharedSecret(
      privateKey: recipientPrivateKey,
      peerPublicKey: ephemeralPublicKey,
    );

    // 3. Derive symmetric key and nonce using HKDF
    final derived = await Hkdf.deriveKey(
      ikm: sharedSecret,
      salt: Uint8List(0),
      info: ephemeralPublicKey,
      keyLength: 44,
    );

    final symKey = derived.sublist(0, 32);
    final nonce = derived.sublist(32, 44);

    // 4. Decrypt using ChaCha20-Poly1305
    return await ChaCha20Poly1305.decrypt(
      key: symKey,
      ciphertext: ciphertext,
      nonce: nonce,
    );
  }
}
