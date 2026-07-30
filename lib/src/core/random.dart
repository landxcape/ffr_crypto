import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffr_crypto_bindings_generated.dart' as bindings;
import '../native/status.dart';
import 'exceptions.dart';

// --- CSPRNG Random ---

class CryptoRandom {
  /// Generates [length] cryptographically secure random bytes.
  static Future<Uint8List> secureBytes(int length) async {
    if (length <= 0) {
      throw InvalidInputException('Length must be greater than zero');
    }

    // We can use direct synchronous run inside Isolate.run to keep UI smooth
    return await Isolate.run(() async {
      final ptr = calloc<ffi.UnsignedChar>(length);
      try {
        final status = bindings.ffr_crypto_random_bytes(ptr, length);
        checkStatus(status, 'Random generation');
        return Uint8List.fromList(ptr.cast<ffi.Uint8>().asTypedList(length));
      } finally {
        calloc.free(ptr);
      }
    });
  }
}
