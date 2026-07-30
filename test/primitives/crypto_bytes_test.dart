import 'dart:convert';
import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_primitives.dart';
import 'package:test/test.dart';

void main() {
  group('strict hexadecimal', () {
    test('decodes mixed case and encodes canonical lowercase', () {
      expect(
        CryptoBytes.decodeHex('00aAFF'),
        Uint8List.fromList([0, 170, 255]),
      );
      expect(
        CryptoBytes.encodeHex(Uint8List.fromList([0, 170, 255])),
        '00aaff',
      );
      expect(CryptoBytes.decodeHex(''), Uint8List(0));
    });

    test('rejects prefixes, odd length, whitespace, and invalid digits', () {
      for (final value in ['0x00', 'abc', 'aa bb', 'gg']) {
        expect(
          () => CryptoBytes.decodeHex(value),
          throwsA(isA<InvalidInputException>()),
          reason: value,
        );
      }
    });
  });

  group('strict Base64', () {
    test('decodes and encodes canonical padded standard Base64', () {
      final expected = Uint8List.fromList(utf8.encode('ffr_crypto'));
      expect(CryptoBytes.decodeBase64('ZmZyX2NyeXB0bw=='), expected);
      expect(CryptoBytes.encodeBase64(expected), 'ZmZyX2NyeXB0bw==');
      expect(CryptoBytes.decodeBase64(''), Uint8List(0));
    });

    test('rejects unpadded, whitespace, URL-safe, and noncanonical text', () {
      for (final value in [
        'ZmZyX2NyeXB0bw',
        'ZmZy X2NyeXB0bw==',
        'ZmZyX2NyeXB0bw__',
        'Zh==',
      ]) {
        expect(
          () => CryptoBytes.decodeBase64(value),
          throwsA(isA<InvalidInputException>()),
          reason: value,
        );
      }
    });
  });

  group('constant-time equality', () {
    test(
      'returns expected results for empty, equal, and unequal values',
      () async {
        final bytes = Uint8List.fromList([1, 2, 3]);
        expect(
          await CryptoBytes.constantTimeEquals(Uint8List(0), Uint8List(0)),
          isTrue,
        );
        expect(
          await CryptoBytes.constantTimeEquals(
            bytes,
            Uint8List.fromList(bytes),
          ),
          isTrue,
        );
        expect(
          await CryptoBytes.constantTimeEquals(
            bytes,
            Uint8List.fromList([1, 2, 4]),
          ),
          isFalse,
        );
        expect(
          await CryptoBytes.constantTimeEquals(bytes, Uint8List(1)),
          isFalse,
        );
      },
    );
  });
}
