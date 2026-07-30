import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_flow.dart';
import 'package:ffr_crypto/ffr_crypto_primitives.dart';
import 'package:test/test.dart';

void main() {
  test('recovers and compares the fixed Node payload end to end', () async {
    final fixture =
        jsonDecode(
              File(
                'test/fixtures/rsa_interop/node_public_recovery.json',
              ).readAsStringSync(),
            )
            as Map<String, Object?>;
    final publicKey = RsaPublicKey(fixture['publicKeyPem']! as String);
    final expected = CryptoBytes.decodeHex(fixture['payloadHex']! as String);

    final valid = await CryptoFlow.fromHex(fixture['transformedHex']! as String)
        .then(RsaSteps.pkcs1v15PublicRecover(publicKey))
        .then(ByteSteps.constantTimeEquals(expected))
        .run();

    expect(valid, isTrue);
  });

  test('fromBytes defensively copies caller input at construction', () async {
    final input = Uint8List.fromList([1, 2, 3]);
    final flow = CryptoFlow.fromBytes(input);
    input[0] = 9;
    expect(await flow.run(), Uint8List.fromList([1, 2, 3]));
  });

  test('strict source failures retain source index zero', () async {
    for (final flow in [
      CryptoFlow.fromHex('0x00'),
      CryptoFlow.fromBase64('Zm8'),
    ]) {
      try {
        await flow.run();
        fail('Expected strict source failure');
      } on CryptoFlowException catch (error) {
        expect(error.stepIndex, 0);
        expect(error.cause, isA<InvalidInputException>());
      }
    }
  });

  test('fromUtf8 accepts pairs and rejects isolated surrogates', () async {
    expect(
      await CryptoFlow.fromUtf8('\u{1F600}').run(),
      Uint8List.fromList(utf8.encode('\u{1F600}')),
    );

    for (final value in [
      String.fromCharCode(0xd800),
      String.fromCharCode(0xdc00),
    ]) {
      await expectLater(
        CryptoFlow.fromUtf8(value).run(),
        throwsA(
          isA<CryptoFlowException>().having(
            (error) => error.cause,
            'cause',
            isA<InvalidInputException>(),
          ),
        ),
      );
    }
  });

  test('hash built-ins match every existing direct algorithm', () async {
    final input = Uint8List.fromList([1, 2, 3]);
    for (final algorithm in HashAlgorithm.values) {
      final expected = await CryptoHash.hash(algorithm, input);
      final actual = await CryptoFlow.fromBytes(
        input,
      ).then(HashSteps.hash(algorithm)).run();
      expect(actual, expected, reason: algorithm.name);
    }
  });

  test('encoding steps preserve typed round trips', () async {
    final bytes = Uint8List.fromList([0, 170, 255]);
    final hexRoundTrip = await CryptoFlow.fromBytes(
      bytes,
    ).then(EncodingSteps.hexEncode()).then(EncodingSteps.hexDecode()).run();
    final base64RoundTrip = await CryptoFlow.fromBytes(bytes)
        .then(EncodingSteps.base64Encode())
        .then(EncodingSteps.base64Decode())
        .run();

    expect(hexRoundTrip, bytes);
    expect(base64RoundTrip, bytes);
  });

  test('one immutable step can be reused in independent flows', () async {
    final step = HashSteps.hash(HashAlgorithm.sha256);
    final first = CryptoFlow.fromBytes(Uint8List.fromList([1])).then(step);
    final second = CryptoFlow.fromBytes(Uint8List.fromList([2])).then(step);

    expect(
      await first.run(),
      await CryptoHash.hash(HashAlgorithm.sha256, Uint8List.fromList([1])),
    );
    expect(
      await second.run(),
      await CryptoHash.hash(HashAlgorithm.sha256, Uint8List.fromList([2])),
    );
  });

  test(
    'custom callback remains an ordered boundary between built-ins',
    () async {
      final input = Uint8List.fromList([1, 2, 3]);
      final expected = await CryptoHash.hash(HashAlgorithm.sha256, input);
      final visited = <String>[];
      final matches = await CryptoFlow.fromBytes(input)
          .then(HashSteps.hash(HashAlgorithm.sha256))
          .thenCustom<Uint8List>('boundary', (digest) {
            visited.add('boundary');
            return digest;
          })
          .then(ByteSteps.constantTimeEquals(expected))
          .run();

      expect(matches, isTrue);
      expect(visited, ['boundary']);
    },
  );
}
