import 'dart:typed_data';

import '../bridge/crypto_bridge.dart';
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

    final res = await CryptoBridge.instance.rsaGenerateKeypair(keySize);
    return RsaKeyPair(
      publicKey: RsaPublicKey(res.publicKeyPem),
      privateKey: RsaPrivateKey(res.privateKeyPem),
    );
  }
}

// --- RSA Engine ---

class Rsa {
  /// Encrypts [plaintext] using RSA-OAEP with SHA-256 padding.
  static Future<Uint8List> encrypt(
    RsaPublicKey publicKey,
    Uint8List plaintext,
  ) async {
    return await CryptoBridge.instance.rsaEncrypt(
      publicKeyPem: publicKey.pem,
      plaintext: plaintext,
    );
  }

  /// Decrypts [ciphertext] using RSA-OAEP with SHA-256 padding.
  static Future<Uint8List> decrypt(
    RsaPrivateKey privateKey,
    Uint8List ciphertext,
  ) async {
    return await CryptoBridge.instance.rsaDecrypt(
      privateKeyPem: privateKey.pem,
      ciphertext: ciphertext,
    );
  }

  /// Signs the SHA-256 [digest] using RSA-PSS.
  static Future<Uint8List> sign(
    RsaPrivateKey privateKey,
    Uint8List digest,
  ) async {
    return await CryptoBridge.instance.rsaSign(
      privateKeyPem: privateKey.pem,
      digest: digest,
    );
  }

  /// Verifies the RSA-PSS signature [signature] against the SHA-256 [digest].
  static Future<bool> verify(
    RsaPublicKey publicKey,
    Uint8List digest,
    Uint8List signature,
  ) async {
    return await CryptoBridge.instance.rsaVerify(
      publicKeyPem: publicKey.pem,
      digest: digest,
      signature: signature,
    );
  }
}
