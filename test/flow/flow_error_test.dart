import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_flow.dart';
import 'package:test/test.dart';

void main() {
  test('wraps lazy source failures at index zero', () async {
    final flow = CryptoFlow.fromHex('not hexadecimal');

    try {
      await flow.run();
      fail('Expected source failure');
    } on CryptoFlowException catch (error) {
      expect(error.stepName, 'source.hex');
      expect(error.stepIndex, 0);
      expect(error.cause, isA<InvalidInputException>());
    }
  });

  test(
    'preserves custom failure name, index, object, and stack trace',
    () async {
      final cause = StateError('custom failure');
      late StackTrace originalStack;
      final flow = CryptoFlow.fromBytes(Uint8List.fromList([1]))
          .thenCustom<int>('first', (_) => 1)
          .thenCustom<String>('second', (_) {
            try {
              throw cause;
            } catch (_, stackTrace) {
              originalStack = stackTrace;
              Error.throwWithStackTrace(cause, stackTrace);
            }
          });

      try {
        await flow.run();
        fail('Expected custom failure');
      } on CryptoFlowException catch (error) {
        expect(error.stepName, 'second');
        expect(error.stepIndex, 2);
        expect(identical(error.cause, cause), isTrue);
        expect(error.causeStackTrace.toString(), originalStack.toString());
        expect(error.toString(), isNot(contains('[1]')));
      }
    },
  );

  test('does not repeatedly nest an existing flow exception', () async {
    final existing = CryptoFlowException(
      stepName: 'existing',
      stepIndex: 7,
      cause: ArgumentError('cause'),
      causeStackTrace: StackTrace.current,
    );
    final flow = CryptoFlow.fromBytes(
      Uint8List(0),
    ).thenCustom<void>('custom', (_) => throw existing);

    await expectLater(flow.run(), throwsA(same(existing)));
  });
}
