import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../core/exceptions.dart';
import '../ffr_crypto_bindings_generated.dart' as bindings;
import '../native/status.dart';

/// Strict byte encoding and comparison utilities.
abstract final class CryptoBytes {
  static final RegExp _hexPattern = RegExp(r'^[0-9a-fA-F]*$');
  static final RegExp _base64Pattern = RegExp(
    r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$',
  );

  /// Decodes even-length hexadecimal without prefixes or whitespace.
  static Uint8List decodeHex(String value) {
    if (value.length.isOdd || !_hexPattern.hasMatch(value)) {
      throw InvalidInputException('Invalid canonical hexadecimal input');
    }

    return Uint8List.fromList([
      for (var index = 0; index < value.length; index += 2)
        int.parse(value.substring(index, index + 2), radix: 16),
    ]);
  }

  /// Encodes bytes as lowercase hexadecimal without a prefix.
  static String encodeHex(Uint8List value) {
    final output = StringBuffer();
    for (final byte in value) {
      output.write(byte.toRadixString(16).padLeft(2, '0'));
    }
    return output.toString();
  }

  /// Decodes canonical padded RFC 4648 standard Base64.
  static Uint8List decodeBase64(String value) {
    if (value.length % 4 != 0 || !_base64Pattern.hasMatch(value)) {
      throw InvalidInputException('Invalid canonical Base64 input');
    }

    try {
      final decoded = base64.decode(value);
      if (base64.encode(decoded) != value) {
        throw InvalidInputException('Invalid canonical Base64 input');
      }
      return Uint8List.fromList(decoded);
    } on FormatException {
      throw InvalidInputException('Invalid canonical Base64 input');
    }
  }

  /// Encodes bytes as canonical padded RFC 4648 standard Base64.
  static String encodeBase64(Uint8List value) => base64.encode(value);

  /// Compares equal-length inputs using Rust's constant-time equality primitive.
  ///
  /// Different public lengths return `false` without comparing contents. This
  /// API does not claim to hide input lengths or prove physical timing behavior.
  static Future<bool> constantTimeEquals(
    Uint8List left,
    Uint8List right,
  ) async {
    if (left.length != right.length) return false;

    return Isolate.run(() {
      final allocationLength = left.isEmpty ? 1 : left.length;
      final leftPointer = calloc<ffi.UnsignedChar>(allocationLength);
      final rightPointer = calloc<ffi.UnsignedChar>(allocationLength);
      final outputPointer = calloc<ffi.UnsignedChar>();
      leftPointer.cast<ffi.Uint8>().asTypedList(left.length).setAll(0, left);
      rightPointer.cast<ffi.Uint8>().asTypedList(right.length).setAll(0, right);

      try {
        final status = bindings.ffr_crypto_constant_time_equals(
          leftPointer,
          left.length,
          rightPointer,
          right.length,
          outputPointer,
        );
        checkStatus(status, 'Constant-time byte comparison');
        return outputPointer.value == 1;
      } finally {
        calloc.free(leftPointer);
        calloc.free(rightPointer);
        calloc.free(outputPointer);
      }
    });
  }
}
