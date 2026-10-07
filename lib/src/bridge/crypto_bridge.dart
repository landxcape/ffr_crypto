import 'dart:typed_data';

import 'bridge_dispatch.dart' as dispatch;

/// Abstract platform bridge defining native/wasm cryptographic operations.
abstract class CryptoBridge {
  static CryptoBridge get instance => dispatch.getBridge();

  Future<Uint8List> randomBytes(int length);

  Future<({String publicKeyPem, String privateKeyPem})> rsaGenerateKeypair(int keySize);

  Future<Uint8List> rsaEncrypt({
    required String publicKeyPem,
    required Uint8List plaintext,
  });

  Future<Uint8List> rsaDecrypt({
    required String privateKeyPem,
    required Uint8List ciphertext,
  });

  Future<Uint8List> rsaSign({
    required String privateKeyPem,
    required Uint8List digest,
  });

  Future<bool> rsaVerify({
    required String publicKeyPem,
    required Uint8List digest,
    required Uint8List signature,
  });

  Future<int> hasherNew(int algorithmId);

  Future<void> hasherUpdate(int hasherHandle, Uint8List data);

  Future<Uint8List> hasherFinalize(int hasherHandle);

  Future<void> hasherFree(int hasherHandle);

  Future<Uint8List> aesGcmEncrypt({
    required Uint8List key,
    required Uint8List plaintext,
    required Uint8List nonce,
    Uint8List? aad,
  });

  Future<Uint8List> aesGcmDecrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    required Uint8List nonce,
    Uint8List? aad,
  });

  Future<Uint8List> chacha20Poly1305Encrypt({
    required Uint8List key,
    required Uint8List plaintext,
    required Uint8List nonce,
    Uint8List? aad,
  });

  Future<Uint8List> chacha20Poly1305Decrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    required Uint8List nonce,
    Uint8List? aad,
  });

  Future<Uint8List> pbkdf2({
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int outputLength,
  });

  Future<Uint8List> hkdf({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    required int outputLength,
  });

  Future<Uint8List> argon2({
    required Uint8List password,
    required Uint8List salt,
    required int mCost,
    required int tCost,
    required int pCost,
    required int variant,
    required int outputLength,
  });

  Future<({Uint8List publicKey, Uint8List privateKey})> ed25519GenerateKeypair();

  Future<Uint8List> ed25519Sign({
    required Uint8List privateKey,
    required Uint8List message,
  });

  Future<bool> ed25519Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  });

  Future<({Uint8List publicKey, Uint8List privateKey})> x25519GenerateKeypair();

  Future<Uint8List> x25519ComputeSharedSecret({
    required Uint8List privateKey,
    required Uint8List peerPublicKey,
  });

  Future<bool> constantTimeEquals({
    required Uint8List left,
    required Uint8List right,
  });

  Future<Uint8List> rsaPkcs1v15PublicRecover({
    required String publicKeyPem,
    required Uint8List input,
  });
}
