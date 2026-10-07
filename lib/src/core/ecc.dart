import 'dart:typed_data';

import '../bridge/crypto_bridge.dart';
import 'exceptions.dart';

// --- Elliptic Curve Cryptography (Ed25519 & X25519) ---

class Ed25519KeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;
  Ed25519KeyPair(this.publicKey, this.privateKey);
}

class Ed25519 {
  static Future<Ed25519KeyPair> generateKeyPair() async {
    final res = await CryptoBridge.instance.ed25519GenerateKeypair();
    return Ed25519KeyPair(res.publicKey, res.privateKey);
  }

  static Future<Uint8List> sign({
    required Uint8List privateKey,
    required Uint8List message,
  }) async {
    if (privateKey.length != 32) {
      throw InvalidKeyException('Ed25519 private key must be 32 bytes');
    }

    return await CryptoBridge.instance.ed25519Sign(
      privateKey: privateKey,
      message: message,
    );
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

    return await CryptoBridge.instance.ed25519Verify(
      publicKey: publicKey,
      message: message,
      signature: signature,
    );
  }
}

class X25519KeyPair {
  final Uint8List publicKey;
  final Uint8List privateKey;
  X25519KeyPair(this.publicKey, this.privateKey);
}

class X25519 {
  static Future<X25519KeyPair> generateKeyPair() async {
    final res = await CryptoBridge.instance.x25519GenerateKeypair();
    return X25519KeyPair(res.publicKey, res.privateKey);
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

    return await CryptoBridge.instance.x25519ComputeSharedSecret(
      privateKey: privateKey,
      peerPublicKey: peerPublicKey,
    );
  }
}
