import '../core/exceptions.dart';

/// Thrown when an RSA PKCS#1 v1.5 block-type-1 payload cannot be recovered.
final class RsaRecoveryException extends CryptoException {
  /// Creates a recovery failure with a non-sensitive [message].
  RsaRecoveryException(super.message);
}
