/// Base exception class for all cryptographic failures.
abstract class CryptoException implements Exception {
  final String message;

  CryptoException(this.message);

  @override
  String toString() => '$runtimeType: $message';
}

class GenericCryptoException extends CryptoException {
  GenericCryptoException(super.message);
}

class InvalidKeyException extends CryptoException {
  InvalidKeyException(super.message);
}

class EncryptionException extends CryptoException {
  EncryptionException(super.message);
}

class DecryptionException extends CryptoException {
  DecryptionException(super.message);
}

class SigningException extends CryptoException {
  SigningException(super.message);
}

class VerificationException extends CryptoException {
  VerificationException(super.message);
}

class InvalidInputException extends CryptoException {
  InvalidInputException(super.message);
}
