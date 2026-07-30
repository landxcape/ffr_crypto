import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_primitives.dart';
import 'package:test/test.dart';

void main() {
  late Map<String, Object?> fixture;
  late RsaPublicKey publicKey;
  late Uint8List transformed;
  late Uint8List expected;

  setUpAll(() {
    fixture =
        jsonDecode(
              File(
                'test/fixtures/rsa_interop/node_public_recovery.json',
              ).readAsStringSync(),
            )
            as Map<String, Object?>;
    publicKey = RsaPublicKey(fixture['publicKeyPem']! as String);
    transformed = _decodeHex(fixture['transformedHex']! as String);
    expected = _decodeHex(fixture['payloadHex']! as String);
  });

  test('recovers a fixed Node-generated payload', () async {
    final recovered = await RsaPkcs1v15.publicRecover(publicKey, transformed);
    expect(recovered, expected);
  });

  test('rejects recovery with a different public key', () async {
    final otherKey = (await RsaKeyPair.generate(2048)).publicKey;
    await expectLater(
      RsaPkcs1v15.publicRecover(otherKey, transformed),
      throwsA(isA<RsaRecoveryException>()),
    );
  });

  test('maps malformed key material to InvalidKeyException', () async {
    await expectLater(
      RsaPkcs1v15.publicRecover(RsaPublicKey('not a key'), transformed),
      throwsA(isA<InvalidKeyException>()),
    );
  });

  test(
    'maps truncated and oversized inputs to InvalidInputException',
    () async {
      await expectLater(
        RsaPkcs1v15.publicRecover(
          publicKey,
          Uint8List.sublistView(transformed, 0, transformed.length - 1),
        ),
        throwsA(isA<InvalidInputException>()),
      );
      await expectLater(
        RsaPkcs1v15.publicRecover(
          publicKey,
          Uint8List.fromList([...transformed, 0]),
        ),
        throwsA(isA<InvalidInputException>()),
      );
    },
  );

  test('maps out-of-range input to RsaRecoveryException', () async {
    await expectLater(
      RsaPkcs1v15.publicRecover(
        publicKey,
        Uint8List.fromList(List.filled(transformed.length, 0xff)),
      ),
      throwsA(isA<RsaRecoveryException>()),
    );
  });

  test('maps a corrupted transformed block to RsaRecoveryException', () async {
    final corrupted = Uint8List.fromList(transformed);
    corrupted[17] ^= 0x01;
    await expectLater(
      RsaPkcs1v15.publicRecover(publicKey, corrupted),
      throwsA(isA<RsaRecoveryException>()),
    );
  });

  test(
    'existing RSA-PSS verification accepts the fixed OpenSSL vector',
    () async {
      final pssFixture =
          jsonDecode(
                File(
                  'test/fixtures/rsa_interop/openssl_pss_sha256.json',
                ).readAsStringSync(),
              )
              as Map<String, Object?>;
      final pssPublicKey = RsaPublicKey(pssFixture['publicKeyPem']! as String);
      final digest = CryptoBytes.decodeHex(pssFixture['digestHex']! as String);
      final signature = CryptoBytes.decodeHex(
        pssFixture['signatureHex']! as String,
      );

      expect(await Rsa.verify(pssPublicKey, digest, signature), isTrue);

      final modifiedDigest = Uint8List.fromList(digest);
      modifiedDigest[0] ^= 0x01;
      expect(
        await Rsa.verify(pssPublicKey, modifiedDigest, signature),
        isFalse,
      );
    },
  );
}

Uint8List _decodeHex(String value) => Uint8List.fromList([
  for (var index = 0; index < value.length; index += 2)
    int.parse(value.substring(index, index + 2), radix: 16),
]);
