import '../core/exceptions.dart';

const int statusSuccess = 0;
const int statusVerificationFailed = 6;
const int statusRsaRecoveryFailed = 8;

void checkStatus(int code, String action) {
  switch (code) {
    case statusSuccess:
      return;
    case 1:
      throw GenericCryptoException('$action failed (Generic Error)');
    case 2:
      throw InvalidKeyException('$action failed: Invalid key format/type');
    case 3:
      throw EncryptionException('$action failed');
    case 4:
      throw DecryptionException('$action failed');
    case 5:
      throw SigningException('$action failed');
    case 6:
      throw VerificationException('$action verification failed');
    case 7:
      throw InvalidInputException('$action failed: Invalid input arguments');
    default:
      throw GenericCryptoException('$action failed with unknown code: $code');
  }
}
