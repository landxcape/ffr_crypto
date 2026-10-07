import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffr_crypto_bindings_generated.dart' as bindings;
import '../native/status.dart';
import '../primitives/exceptions.dart';
import 'crypto_bridge.dart';

CryptoBridge getBridge() => BridgeFfi();

class BridgeFfi implements CryptoBridge {
  @override
  Future<Uint8List> randomBytes(int length) async {
    return await Isolate.run(() async {
      final ptr = calloc<ffi.UnsignedChar>(length);
      try {
        final status = bindings.ffr_crypto_random_bytes(ptr, length);
        checkStatus(status, 'Random generation');
        return Uint8List.fromList(ptr.cast<ffi.Uint8>().asTypedList(length));
      } finally {
        calloc.free(ptr);
      }
    });
  }

  @override
  Future<({String publicKeyPem, String privateKeyPem})> rsaGenerateKeypair(int keySize) async {
    return await Isolate.run(() async {
      final pubPemPtr = calloc<ffi.Pointer<ffi.Char>>();
      final privPemPtr = calloc<ffi.Pointer<ffi.Char>>();
      try {
        final status = bindings.ffr_crypto_rsa_generate_keypair(keySize, pubPemPtr, privPemPtr);
        checkStatus(status, 'RSA key generation');
        final pubStr = pubPemPtr.value.cast<Utf8>().toDartString();
        final privStr = privPemPtr.value.cast<Utf8>().toDartString();
        bindings.ffr_crypto_free_string(pubPemPtr.value);
        bindings.ffr_crypto_free_string(privPemPtr.value);
        return (publicKeyPem: pubStr, privateKeyPem: privStr);
      } finally {
        calloc.free(pubPemPtr);
        calloc.free(privPemPtr);
      }
    });
  }

  @override
  Future<Uint8List> rsaEncrypt({required String publicKeyPem, required Uint8List plaintext}) async {
    return await Isolate.run(() async {
      final pubKeyPtr = publicKeyPem.toNativeUtf8();
      final plaintextPtr = calloc<ffi.UnsignedChar>(plaintext.length);
      plaintextPtr.cast<ffi.Uint8>().asTypedList(plaintext.length).setAll(0, plaintext);
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
        final outLen = outLenPtr.value;
        final result = Uint8List.fromList(outCiphertextPtr.value.cast<ffi.Uint8>().asTypedList(outLen));
        bindings.ffr_crypto_free_bytes(outCiphertextPtr.value, outLen);
        return result;
      } finally {
        calloc.free(pubKeyPtr);
        calloc.free(plaintextPtr);
        calloc.free(outCiphertextPtr);
        calloc.free(outLenPtr);
      }
    });
  }

  @override
  Future<Uint8List> rsaDecrypt({required String privateKeyPem, required Uint8List ciphertext}) async {
    return await Isolate.run(() async {
      final privKeyPtr = privateKeyPem.toNativeUtf8();
      final ciphertextPtr = calloc<ffi.UnsignedChar>(ciphertext.length);
      ciphertextPtr.cast<ffi.Uint8>().asTypedList(ciphertext.length).setAll(0, ciphertext);
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
        final outLen = outLenPtr.value;
        final result = Uint8List.fromList(outPlaintextPtr.value.cast<ffi.Uint8>().asTypedList(outLen));
        bindings.ffr_crypto_free_bytes(outPlaintextPtr.value, outLen);
        return result;
      } finally {
        calloc.free(privKeyPtr);
        calloc.free(ciphertextPtr);
        calloc.free(outPlaintextPtr);
        calloc.free(outLenPtr);
      }
    });
  }

  @override
  Future<Uint8List> rsaSign({required String privateKeyPem, required Uint8List digest}) async {
    return await Isolate.run(() async {
      final privKeyPtr = privateKeyPem.toNativeUtf8();
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
        final outLen = outSigLenPtr.value;
        final result = Uint8List.fromList(outSigPtr.value.cast<ffi.Uint8>().asTypedList(outLen));
        bindings.ffr_crypto_free_bytes(outSigPtr.value, outLen);
        return result;
      } finally {
        calloc.free(privKeyPtr);
        calloc.free(digestPtr);
        calloc.free(outSigPtr);
        calloc.free(outSigLenPtr);
      }
    });
  }

  @override
  Future<bool> rsaVerify({
    required String publicKeyPem,
    required Uint8List digest,
    required Uint8List signature,
  }) async {
    return await Isolate.run(() async {
      final pubKeyPtr = publicKeyPem.toNativeUtf8();
      final digestPtr = calloc<ffi.UnsignedChar>(digest.length);
      digestPtr.cast<ffi.Uint8>().asTypedList(digest.length).setAll(0, digest);
      final sigPtr = calloc<ffi.UnsignedChar>(signature.length);
      sigPtr.cast<ffi.Uint8>().asTypedList(signature.length).setAll(0, signature);
      try {
        final status = bindings.ffr_crypto_rsa_verify(
          pubKeyPtr.cast<ffi.Char>(),
          digestPtr,
          digest.length,
          sigPtr,
          signature.length,
        );
        if (status == statusSuccess) return true;
        if (status == statusVerificationFailed) return false;
        checkStatus(status, 'RSA verification');
        return false;
      } finally {
        calloc.free(pubKeyPtr);
        calloc.free(digestPtr);
        calloc.free(sigPtr);
      }
    });
  }

  @override
  Future<int> hasherNew(int algorithmId) async {
    return await Isolate.run(() async {
      final outPtr = calloc<ffi.Pointer<bindings.HasherContext>>();
      try {
        final status = bindings.ffr_crypto_hasher_new(algorithmId, outPtr);
        checkStatus(status, 'Hasher initialization');
        return outPtr.value.address;
      } finally {
        calloc.free(outPtr);
      }
    });
  }

  @override
  Future<void> hasherUpdate(int hasherHandle, Uint8List data) async {
    await Isolate.run(() async {
      final dataPtr = calloc<ffi.UnsignedChar>(data.length);
      dataPtr.cast<ffi.Uint8>().asTypedList(data.length).setAll(0, data);
      try {
        final status = bindings.ffr_crypto_hasher_update(
          ffi.Pointer.fromAddress(hasherHandle),
          dataPtr,
          data.length,
        );
        checkStatus(status, 'Hasher update');
      } finally {
        calloc.free(dataPtr);
      }
    });
  }

  @override
  Future<Uint8List> hasherFinalize(int hasherHandle) async {
    return await Isolate.run(() async {
      final outDigestPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outLenPtr = calloc<ffi.Size>();
      try {
        final status = bindings.ffr_crypto_hasher_finalize(
          ffi.Pointer.fromAddress(hasherHandle),
          outDigestPtr,
          outLenPtr,
        );
        checkStatus(status, 'Hasher finalize');
        final outLen = outLenPtr.value;
        final result = Uint8List.fromList(outDigestPtr.value.cast<ffi.Uint8>().asTypedList(outLen));
        bindings.ffr_crypto_free_bytes(outDigestPtr.value, outLen);
        return result;
      } finally {
        calloc.free(outDigestPtr);
        calloc.free(outLenPtr);
      }
    });
  }

  @override
  Future<void> hasherFree(int hasherHandle) async {
    bindings.ffr_crypto_hasher_free(ffi.Pointer.fromAddress(hasherHandle));
  }

  @override
  Future<Uint8List> aesGcmEncrypt({
    required Uint8List key,
    required Uint8List plaintext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    return await Isolate.run(() async {
      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      keyPtr.cast<ffi.Uint8>().asTypedList(key.length).setAll(0, key);
      final plaintextPtr = calloc<ffi.UnsignedChar>(plaintext.length);
      plaintextPtr.cast<ffi.Uint8>().asTypedList(plaintext.length).setAll(0, plaintext);
      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      noncePtr.cast<ffi.Uint8>().asTypedList(nonce.length).setAll(0, nonce);
      final aadLength = aad?.length ?? 0;
      final aadPtr = aadLength > 0 ? calloc<ffi.UnsignedChar>(aadLength) : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
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
        final outLen = outLenPtr.value;
        final result = Uint8List.fromList(outCiphertextPtr.value.cast<ffi.Uint8>().asTypedList(outLen));
        bindings.ffr_crypto_free_bytes(outCiphertextPtr.value, outLen);
        return result;
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

  @override
  Future<Uint8List> aesGcmDecrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    return await Isolate.run(() async {
      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      keyPtr.cast<ffi.Uint8>().asTypedList(key.length).setAll(0, key);
      final ciphertextPtr = calloc<ffi.UnsignedChar>(ciphertext.length);
      ciphertextPtr.cast<ffi.Uint8>().asTypedList(ciphertext.length).setAll(0, ciphertext);
      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      noncePtr.cast<ffi.Uint8>().asTypedList(nonce.length).setAll(0, nonce);
      final aadLength = aad?.length ?? 0;
      final aadPtr = aadLength > 0 ? calloc<ffi.UnsignedChar>(aadLength) : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
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
        final outLen = outLenPtr.value;
        final result = Uint8List.fromList(outPlaintextPtr.value.cast<ffi.Uint8>().asTypedList(outLen));
        bindings.ffr_crypto_free_bytes(outPlaintextPtr.value, outLen);
        return result;
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

  @override
  Future<Uint8List> chacha20Poly1305Encrypt({
    required Uint8List key,
    required Uint8List plaintext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    return await Isolate.run(() async {
      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      keyPtr.cast<ffi.Uint8>().asTypedList(key.length).setAll(0, key);
      final plaintextPtr = calloc<ffi.UnsignedChar>(plaintext.length);
      plaintextPtr.cast<ffi.Uint8>().asTypedList(plaintext.length).setAll(0, plaintext);
      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      noncePtr.cast<ffi.Uint8>().asTypedList(nonce.length).setAll(0, nonce);
      final aadLength = aad?.length ?? 0;
      final aadPtr = aadLength > 0 ? calloc<ffi.UnsignedChar>(aadLength) : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
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
        final outLen = outLenPtr.value;
        final result = Uint8List.fromList(outCiphertextPtr.value.cast<ffi.Uint8>().asTypedList(outLen));
        bindings.ffr_crypto_free_bytes(outCiphertextPtr.value, outLen);
        return result;
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

  @override
  Future<Uint8List> chacha20Poly1305Decrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    return await Isolate.run(() async {
      final keyPtr = calloc<ffi.UnsignedChar>(key.length);
      keyPtr.cast<ffi.Uint8>().asTypedList(key.length).setAll(0, key);
      final ciphertextPtr = calloc<ffi.UnsignedChar>(ciphertext.length);
      ciphertextPtr.cast<ffi.Uint8>().asTypedList(ciphertext.length).setAll(0, ciphertext);
      final noncePtr = calloc<ffi.UnsignedChar>(nonce.length);
      noncePtr.cast<ffi.Uint8>().asTypedList(nonce.length).setAll(0, nonce);
      final aadLength = aad?.length ?? 0;
      final aadPtr = aadLength > 0 ? calloc<ffi.UnsignedChar>(aadLength) : ffi.Pointer<ffi.UnsignedChar>.fromAddress(0);
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
        final outLen = outLenPtr.value;
        final result = Uint8List.fromList(outPlaintextPtr.value.cast<ffi.Uint8>().asTypedList(outLen));
        bindings.ffr_crypto_free_bytes(outPlaintextPtr.value, outLen);
        return result;
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

  @override
  Future<Uint8List> pbkdf2({
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int outputLength,
  }) async {
    return await Isolate.run(() async {
      final passwordPtr = calloc<ffi.UnsignedChar>(password.length);
      passwordPtr.cast<ffi.Uint8>().asTypedList(password.length).setAll(0, password);
      final saltPtr = calloc<ffi.UnsignedChar>(salt.length);
      saltPtr.cast<ffi.Uint8>().asTypedList(salt.length).setAll(0, salt);
      final outKeyPtr = calloc<ffi.UnsignedChar>(outputLength);
      try {
        final status = bindings.ffr_crypto_pbkdf2(
          passwordPtr,
          password.length,
          saltPtr,
          salt.length,
          iterations,
          outKeyPtr,
          outputLength,
        );
        checkStatus(status, 'PBKDF2 key derivation');
        return Uint8List.fromList(outKeyPtr.cast<ffi.Uint8>().asTypedList(outputLength));
      } finally {
        calloc.free(passwordPtr);
        calloc.free(saltPtr);
        calloc.free(outKeyPtr);
      }
    });
  }

  @override
  Future<Uint8List> hkdf({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    required int outputLength,
  }) async {
    return await Isolate.run(() async {
      final ikmPtr = calloc<ffi.UnsignedChar>(ikm.length);
      ikmPtr.cast<ffi.Uint8>().asTypedList(ikm.length).setAll(0, ikm);
      final saltPtr = calloc<ffi.UnsignedChar>(salt.length);
      saltPtr.cast<ffi.Uint8>().asTypedList(salt.length).setAll(0, salt);
      final infoPtr = calloc<ffi.UnsignedChar>(info.length);
      infoPtr.cast<ffi.Uint8>().asTypedList(info.length).setAll(0, info);
      final outKeyPtr = calloc<ffi.UnsignedChar>(outputLength);
      try {
        final status = bindings.ffr_crypto_hkdf(
          ikmPtr,
          ikm.length,
          saltPtr,
          salt.length,
          infoPtr,
          info.length,
          outKeyPtr,
          outputLength,
        );
        checkStatus(status, 'HKDF key derivation');
        return Uint8List.fromList(outKeyPtr.cast<ffi.Uint8>().asTypedList(outputLength));
      } finally {
        calloc.free(ikmPtr);
        calloc.free(saltPtr);
        calloc.free(infoPtr);
        calloc.free(outKeyPtr);
      }
    });
  }

  @override
  Future<Uint8List> argon2({
    required Uint8List password,
    required Uint8List salt,
    required int mCost,
    required int tCost,
    required int pCost,
    required int variant,
    required int outputLength,
  }) async {
    return await Isolate.run(() async {
      final passwordPtr = calloc<ffi.UnsignedChar>(password.length);
      passwordPtr.cast<ffi.Uint8>().asTypedList(password.length).setAll(0, password);
      final saltPtr = calloc<ffi.UnsignedChar>(salt.length);
      saltPtr.cast<ffi.Uint8>().asTypedList(salt.length).setAll(0, salt);
      final outKeyPtr = calloc<ffi.UnsignedChar>(outputLength);
      try {
        final status = bindings.ffr_crypto_argon2(
          passwordPtr,
          password.length,
          saltPtr,
          salt.length,
          mCost,
          tCost,
          pCost,
          variant,
          outKeyPtr,
          outputLength,
        );
        checkStatus(status, 'Argon2 key derivation');
        return Uint8List.fromList(outKeyPtr.cast<ffi.Uint8>().asTypedList(outputLength));
      } finally {
        calloc.free(passwordPtr);
        calloc.free(saltPtr);
        calloc.free(outKeyPtr);
      }
    });
  }

  @override
  Future<({Uint8List publicKey, Uint8List privateKey})> ed25519GenerateKeypair() async {
    return await Isolate.run(() async {
      final pubPtr = calloc<ffi.UnsignedChar>(32);
      final privPtr = calloc<ffi.UnsignedChar>(32);
      try {
        final status = bindings.ffr_crypto_ed25519_generate_keypair(pubPtr, privPtr);
        checkStatus(status, 'Ed25519 key generation');
        final pubBytes = Uint8List.fromList(pubPtr.cast<ffi.Uint8>().asTypedList(32));
        final privBytes = Uint8List.fromList(privPtr.cast<ffi.Uint8>().asTypedList(32));
        return (publicKey: pubBytes, privateKey: privBytes);
      } finally {
        calloc.free(pubPtr);
        calloc.free(privPtr);
      }
    });
  }

  @override
  Future<Uint8List> ed25519Sign({required Uint8List privateKey, required Uint8List message}) async {
    return await Isolate.run(() async {
      final privPtr = calloc<ffi.UnsignedChar>(32);
      privPtr.cast<ffi.Uint8>().asTypedList(32).setAll(0, privateKey);
      final msgPtr = calloc<ffi.UnsignedChar>(message.length);
      msgPtr.cast<ffi.Uint8>().asTypedList(message.length).setAll(0, message);
      final sigPtr = calloc<ffi.UnsignedChar>(64);
      try {
        final status = bindings.ffr_crypto_ed25519_sign(privPtr, msgPtr, message.length, sigPtr);
        checkStatus(status, 'Ed25519 signing');
        return Uint8List.fromList(sigPtr.cast<ffi.Uint8>().asTypedList(64));
      } finally {
        calloc.free(privPtr);
        calloc.free(msgPtr);
        calloc.free(sigPtr);
      }
    });
  }

  @override
  Future<bool> ed25519Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) async {
    return await Isolate.run(() async {
      final pubPtr = calloc<ffi.UnsignedChar>(32);
      pubPtr.cast<ffi.Uint8>().asTypedList(32).setAll(0, publicKey);
      final msgPtr = calloc<ffi.UnsignedChar>(message.length);
      msgPtr.cast<ffi.Uint8>().asTypedList(message.length).setAll(0, message);
      final sigPtr = calloc<ffi.UnsignedChar>(64);
      sigPtr.cast<ffi.Uint8>().asTypedList(64).setAll(0, signature);
      try {
        final status = bindings.ffr_crypto_ed25519_verify(pubPtr, msgPtr, message.length, sigPtr);
        if (status == statusSuccess) return true;
        if (status == statusVerificationFailed) return false;
        checkStatus(status, 'Ed25519 verification');
        return false;
      } finally {
        calloc.free(pubPtr);
        calloc.free(msgPtr);
        calloc.free(sigPtr);
      }
    });
  }

  @override
  Future<({Uint8List publicKey, Uint8List privateKey})> x25519GenerateKeypair() async {
    return await Isolate.run(() async {
      final pubPtr = calloc<ffi.UnsignedChar>(32);
      final privPtr = calloc<ffi.UnsignedChar>(32);
      try {
        final status = bindings.ffr_crypto_x25519_generate_keypair(pubPtr, privPtr);
        checkStatus(status, 'X25519 key generation');
        final pubBytes = Uint8List.fromList(pubPtr.cast<ffi.Uint8>().asTypedList(32));
        final privBytes = Uint8List.fromList(privPtr.cast<ffi.Uint8>().asTypedList(32));
        return (publicKey: pubBytes, privateKey: privBytes);
      } finally {
        calloc.free(pubPtr);
        calloc.free(privPtr);
      }
    });
  }

  @override
  Future<Uint8List> x25519ComputeSharedSecret({
    required Uint8List privateKey,
    required Uint8List peerPublicKey,
  }) async {
    return await Isolate.run(() async {
      final privPtr = calloc<ffi.UnsignedChar>(32);
      privPtr.cast<ffi.Uint8>().asTypedList(32).setAll(0, privateKey);
      final peerPtr = calloc<ffi.UnsignedChar>(32);
      peerPtr.cast<ffi.Uint8>().asTypedList(32).setAll(0, peerPublicKey);
      final outPtr = calloc<ffi.UnsignedChar>(32);
      try {
        final status = bindings.ffr_crypto_x25519_compute_shared_secret(privPtr, peerPtr, outPtr);
        checkStatus(status, 'X25519 shared secret');
        return Uint8List.fromList(outPtr.cast<ffi.Uint8>().asTypedList(32));
      } finally {
        calloc.free(privPtr);
        calloc.free(peerPtr);
        calloc.free(outPtr);
      }
    });
  }

  @override
  Future<bool> constantTimeEquals({required Uint8List left, required Uint8List right}) async {
    return await Isolate.run(() {
      final leftPtr = calloc<ffi.UnsignedChar>(left.length);
      leftPtr.cast<ffi.Uint8>().asTypedList(left.length).setAll(0, left);
      final rightPtr = calloc<ffi.UnsignedChar>(right.length);
      rightPtr.cast<ffi.Uint8>().asTypedList(right.length).setAll(0, right);
      final outEqual = calloc<ffi.UnsignedChar>(1);
      try {
        final status = bindings.ffr_crypto_constant_time_equals(
          leftPtr,
          left.length,
          rightPtr,
          right.length,
          outEqual,
        );
        checkStatus(status, 'Constant-time comparison');
        return outEqual.value != 0;
      } finally {
        calloc.free(leftPtr);
        calloc.free(rightPtr);
        calloc.free(outEqual);
      }
    });
  }

  @override
  Future<Uint8List> rsaPkcs1v15PublicRecover({
    required String publicKeyPem,
    required Uint8List input,
  }) async {
    return await Isolate.run(() {
      final publicKeyPointer = publicKeyPem.toNativeUtf8();
      final inputPointer = calloc<ffi.UnsignedChar>(input.length);
      inputPointer.cast<ffi.Uint8>().asTypedList(input.length).setAll(0, input);
      final outputPointer = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outputLength = calloc<ffi.Size>();
      try {
        final status = bindings.ffr_crypto_rsa_pkcs1v15_public_recover(
          publicKeyPointer.cast<ffi.Char>(),
          inputPointer,
          input.length,
          outputPointer,
          outputLength,
        );
        switch (status) {
          case statusSuccess:
            break;
          case statusRsaRecoveryFailed:
            throw RsaRecoveryException('RSA PKCS#1 v1.5 public recovery failed');
          default:
            checkStatus(status, 'RSA PKCS#1 v1.5 public recovery');
        }
        final length = outputLength.value;
        final result = Uint8List.fromList(outputPointer.value.cast<ffi.Uint8>().asTypedList(length));
        bindings.ffr_crypto_free_bytes(outputPointer.value, length);
        return result;
      } finally {
        calloc.free(publicKeyPointer);
        calloc.free(inputPointer);
        calloc.free(outputPointer);
        calloc.free(outputLength);
      }
    });
  }
}
