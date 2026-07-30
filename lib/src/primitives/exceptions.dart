import '../core/exceptions.dart';

/// Thrown when an RSA PKCS#1 v1.5 block-type-1 payload cannot be recovered.
///
/// The failure intentionally does not reveal which block validation check
/// rejected the input.
final class RsaRecoveryException extends CryptoException {
  /// Creates a recovery failure with a non-sensitive [message].
  RsaRecoveryException(super.message);
}
