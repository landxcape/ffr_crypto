import 'dart:typed_data';

import '../bridge/crypto_bridge.dart';
import '../core/rsa.dart';
import 'exceptions.dart';

/// Advanced RSA PKCS#1 v1.5 block-type-1 compatibility primitives.
abstract final class RsaPkcs1v15 {
  /// Applies the RSA public operation to [transformedBlock], validates the full
  /// block-type-1 encoding, and returns its arbitrary non-empty payload.
  ///
  /// This operation is payload recovery for compatibility protocols. It does
  /// not perform standards-compliant RSASSA-PKCS1-v1_5 signature verification
  /// and does not interpret or validate the recovered payload's meaning.
  ///
  /// [publicKey] may contain SPKI (`PUBLIC KEY`) or PKCS#1 (`RSA PUBLIC KEY`)
  /// PEM. [transformedBlock] must be exactly the encoded RSA modulus length and
  /// represent an integer smaller than the modulus.
  ///
  /// Malformed keys use the core package's invalid-key failure. Invalid block
  /// lengths, representatives, encodings, and empty payloads throw
  /// [RsaRecoveryException] without identifying the rejected recovery check.
  static Future<Uint8List> publicRecover(
    RsaPublicKey publicKey,
    Uint8List transformedBlock,
  ) async {
    return await CryptoBridge.instance.rsaPkcs1v15PublicRecover(
      publicKeyPem: publicKey.pem,
      input: transformedBlock,
    );
  }
}
