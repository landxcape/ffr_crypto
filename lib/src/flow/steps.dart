part of '../../ffr_crypto_flow.dart';

final class _RsaPublicRecoverDescriptor extends _NativeStepDescriptor {
  final RsaPublicKey publicKey;

  const _RsaPublicRecoverDescriptor(this.publicKey);
}

final class _HashDescriptor extends _NativeStepDescriptor {
  final HashAlgorithm algorithm;

  const _HashDescriptor(this.algorithm);
}

final class _ByteEqualsDescriptor extends _NativeStepDescriptor {
  final Uint8List expected;

  const _ByteEqualsDescriptor(this.expected);
}

enum _EncodingOperation { hexDecode, hexEncode, base64Decode, base64Encode }

final class _EncodingDescriptor extends _NativeStepDescriptor {
  final _EncodingOperation operation;

  const _EncodingDescriptor(this.operation);
}

/// Factory namespace for advanced RSA flow steps.
abstract final class RsaSteps {
  /// Recovers a validated PKCS#1 v1.5 block-type-1 payload.
  static CryptoStep<Uint8List, Uint8List> pkcs1v15PublicRecover(
    RsaPublicKey publicKey,
  ) => _OperationStep(
    'rsa.pkcs1v15.publicRecover',
    (input) => RsaPkcs1v15.publicRecover(publicKey, input),
    _RsaPublicRecoverDescriptor(publicKey),
  );
}

/// Factory namespace for hashing flow steps.
abstract final class HashSteps {
  /// Hashes bytes with one of the existing package algorithms.
  static CryptoStep<Uint8List, Uint8List> hash(HashAlgorithm algorithm) =>
      _OperationStep(
        'hash.${algorithm.name}',
        (input) => CryptoHash.hash(algorithm, input),
        _HashDescriptor(algorithm),
      );
}

/// Factory namespace for byte-oriented flow steps.
abstract final class ByteSteps {
  /// Compares the current bytes with a defensively retained expected value.
  static CryptoStep<Uint8List, bool> constantTimeEquals(Uint8List expected) {
    final retained = Uint8List.fromList(expected);
    return _OperationStep(
      'bytes.constantTimeEquals',
      (input) => CryptoBytes.constantTimeEquals(input, retained),
      _ByteEqualsDescriptor(retained),
    );
  }
}

/// Factory namespace for strict text/byte encoding flow steps.
abstract final class EncodingSteps {
  /// Decodes strict hexadecimal text to bytes.
  static CryptoStep<String, Uint8List> hexDecode() => const _OperationStep(
    'encoding.hex.decode',
    CryptoBytes.decodeHex,
    _EncodingDescriptor(_EncodingOperation.hexDecode),
  );

  /// Encodes bytes as canonical lowercase hexadecimal.
  static CryptoStep<Uint8List, String> hexEncode() => const _OperationStep(
    'encoding.hex.encode',
    CryptoBytes.encodeHex,
    _EncodingDescriptor(_EncodingOperation.hexEncode),
  );

  /// Decodes strict canonical standard Base64 text to bytes.
  static CryptoStep<String, Uint8List> base64Decode() => const _OperationStep(
    'encoding.base64.decode',
    CryptoBytes.decodeBase64,
    _EncodingDescriptor(_EncodingOperation.base64Decode),
  );

  /// Encodes bytes as canonical padded standard Base64.
  static CryptoStep<Uint8List, String> base64Encode() => const _OperationStep(
    'encoding.base64.encode',
    CryptoBytes.encodeBase64,
    _EncodingDescriptor(_EncodingOperation.base64Encode),
  );
}
