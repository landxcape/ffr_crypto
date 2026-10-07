import 'dart:typed_data';

import '../bridge/crypto_bridge.dart';
import 'exceptions.dart';

// --- CSPRNG Random ---

class CryptoRandom {
  /// Generates [length] cryptographically secure random bytes.
  static Future<Uint8List> secureBytes(int length) async {
    if (length <= 0) {
      throw InvalidInputException('Length must be greater than zero');
    }

    return await CryptoBridge.instance.randomBytes(length);
  }
}
