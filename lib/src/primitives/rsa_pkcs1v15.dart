import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../core/rsa.dart';
import '../ffr_crypto_bindings_generated.dart' as bindings;
import '../native/status.dart';
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
    return Isolate.run(() {
      final publicKeyPointer = publicKey.pem.toNativeUtf8();
      final inputPointer = calloc<ffi.UnsignedChar>(transformedBlock.length);
      inputPointer
          .cast<ffi.Uint8>()
          .asTypedList(transformedBlock.length)
          .setAll(0, transformedBlock);
      final outputPointer = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outputLength = calloc<ffi.Size>();

      try {
        final status = bindings.ffr_crypto_rsa_pkcs1v15_public_recover(
          publicKeyPointer.cast<ffi.Char>(),
          inputPointer,
          transformedBlock.length,
          outputPointer,
          outputLength,
        );
        switch (status) {
          case statusSuccess:
            break;
          case statusRsaRecoveryFailed:
            throw RsaRecoveryException(
              'RSA PKCS#1 v1.5 public recovery failed',
            );
          default:
            checkStatus(status, 'RSA PKCS#1 v1.5 public recovery');
        }

        final resultPointer = outputPointer.value;
        final resultLength = outputLength.value;
        try {
          return Uint8List.fromList(
            resultPointer.cast<ffi.Uint8>().asTypedList(resultLength),
          );
        } finally {
          bindings.ffr_crypto_free_bytes(resultPointer, resultLength);
        }
      } finally {
        calloc.free(publicKeyPointer);
        calloc.free(inputPointer);
        calloc.free(outputPointer);
        calloc.free(outputLength);
      }
    });
  }
}
