import 'dart:async';
import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto_flow.dart';
import 'package:test/test.dart';

void main() {
  test('cancellation before run prevents lazy source evaluation', () async {
    final token = CryptoCancellationToken()..cancel();
    final flow = CryptoFlow.fromHex('not hexadecimal');

    await expectLater(
      flow.run(cancellationToken: token),
      throwsA(isA<CryptoFlowCancelledException>()),
    );
  });

  test('cancellation between steps prevents the next step', () async {
    final token = CryptoCancellationToken();
    var nextRan = false;
    final flow = CryptoFlow.fromBytes(Uint8List.fromList([1]))
        .thenCustom<Uint8List>('cancel', (value) {
          token.cancel();
          return value;
        })
        .thenCustom<bool>('must not run', (_) {
          nextRan = true;
          return true;
        });

    await expectLater(
      flow.run(cancellationToken: token),
      throwsA(isA<CryptoFlowCancelledException>()),
    );
    expect(nextRan, isFalse);
  });

  test(
    'active async step completes cleanup before cancellation is observed',
    () async {
      final token = CryptoCancellationToken();
      final started = Completer<void>();
      final release = Completer<void>();
      var cleaned = false;
      var nextRan = false;

      final flow = CryptoFlow.fromBytes(Uint8List.fromList([1]))
          .thenCustom<Uint8List>('wait', (value) async {
            started.complete();
            try {
              await release.future;
              return value;
            } finally {
              cleaned = true;
            }
          })
          .thenCustom<bool>('must not run', (_) {
            nextRan = true;
            return true;
          });

      final running = flow.run(cancellationToken: token);
      await started.future;
      token.cancel();
      release.complete();

      await expectLater(running, throwsA(isA<CryptoFlowCancelledException>()));
      expect(cleaned, isTrue);
      expect(nextRan, isFalse);
    },
  );

  test('ordinary custom failure still runs callback cleanup', () async {
    var cleaned = false;
    final flow = CryptoFlow.fromBytes(Uint8List(0)).thenCustom<void>('fail', (
      _,
    ) {
      try {
        throw StateError('failure');
      } finally {
        cleaned = true;
      }
    });

    await expectLater(flow.run(), throwsA(isA<CryptoFlowException>()));
    expect(cleaned, isTrue);
  });
}
