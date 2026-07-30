import 'dart:convert';
import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_flow.dart';
import 'package:test/test.dart';

void main() {
  test(
    'executes typed synchronous and asynchronous custom steps in order',
    () async {
      final visited = <String>[];
      final flow = CryptoFlow.fromUtf8('abc')
          .thenCustom<int>('length', (bytes) {
            visited.add('length');
            return bytes.length;
          })
          .thenCustom<String>('describe', (length) async {
            visited.add('describe');
            return 'length=$length';
          });

      final String result = await flow.run();
      expect(result, 'length=3');
      expect(visited, ['length', 'describe']);
      await expectLater(flow.run(), throwsA(isA<CryptoFlowStateException>()));
    },
  );

  test(
    'original and extended immutable flows have independent lifecycles',
    () async {
      final source = CryptoFlow.fromUtf8('abc');
      final extended = source.thenCustom<int>(
        'length',
        (bytes) => bytes.length,
      );

      expect(await source.run(), Uint8List.fromList(utf8.encode('abc')));
      expect(await extended.run(), 3);
      await expectLater(source.run(), throwsA(isA<CryptoFlowStateException>()));
      await expectLater(
        extended.run(),
        throwsA(isA<CryptoFlowStateException>()),
      );
    },
  );

  test('custom callback can invoke a Rust-backed direct API', () async {
    final input = Uint8List.fromList([1, 2, 3]);
    final expected = await CryptoHash.hash(HashAlgorithm.sha256, input);
    final actual = await CryptoFlow.fromBytes(input)
        .thenCustom<Uint8List>(
          'direct hash',
          (bytes) => CryptoHash.hash(HashAlgorithm.sha256, bytes),
        )
        .run();

    expect(actual, expected);
  });

  test('rejects empty custom step names during construction', () {
    expect(
      () => CryptoFlow.fromBytes(Uint8List(0)).thenCustom<int>('  ', (_) => 1),
      throwsA(isA<InvalidInputException>()),
    );
  });
}
