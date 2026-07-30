import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffr_crypto_bindings_generated.dart' as bindings;
import '../native/status.dart';
import 'exceptions.dart';

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
        checkStatus(status, 'RSA key generation');

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
        checkStatus(status, 'RSA encryption');

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
        checkStatus(status, 'RSA decryption');

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
        checkStatus(status, 'RSA signing');

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

        checkStatus(status, 'RSA verification');
        return false;
      } finally {
        calloc.free(pubKeyPtr);
        calloc.free(digestPtr);
        calloc.free(signaturePtr);
      }
    });
  }
}
