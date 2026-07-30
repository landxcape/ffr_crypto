import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffr_crypto_bindings_generated.dart' as bindings;
import '../native/status.dart';
import 'exceptions.dart';

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
        checkStatus(status, 'Ed25519 key generation');

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
        checkStatus(status, 'Ed25519 signing');
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
        checkStatus(status, 'Ed25519 verification');
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
        checkStatus(status, 'X25519 key generation');

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
        checkStatus(status, 'X25519 secret agreement');
        return Uint8List.fromList(secretPtr.cast<ffi.Uint8>().asTypedList(32));
      } finally {
        calloc.free(privPtr);
        calloc.free(pubPtr);
        calloc.free(secretPtr);
      }
    });
  }
}
