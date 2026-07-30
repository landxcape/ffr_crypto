import 'dart:io';
import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_flow.dart';
import 'package:ffr_crypto/ffr_crypto_primitives.dart';
import 'package:test/test.dart';

void main() {
  test('analyzer rejects incompatible adjacent step types', () async {
    final generatedDirectory = Directory(
      '.dart_tool/ffr_crypto_analyzer_fixtures',
    );
    final generatedFile = File(
      '${generatedDirectory.path}/incompatible_steps.dart',
    );
    await generatedDirectory.create(recursive: true);
    await File(
      'test/analyzer_fixtures/incompatible_steps.dart.txt',
    ).copy(generatedFile.path);

    try {
      final result = await Process.run(Platform.resolvedExecutable, [
        'analyze',
        generatedFile.path,
      ], workingDirectory: Directory.current.path);
      final output = '${result.stdout}\n${result.stderr}';
      expect(result.exitCode, isNonZero);
      expect(output, contains('argument_type_not_assignable'));
    } finally {
      if (await generatedFile.exists()) {
        await generatedFile.delete();
      }
    }
  });

  test('valid flow uses three explicit isolated imports', () async {
    final input = Uint8List.fromList([1, 2, 3]);
    final expected = await CryptoHash.hash(HashAlgorithm.sha256, input);
    final matches = await CryptoFlow.fromBytes(input)
        .then(HashSteps.hash(HashAlgorithm.sha256))
        .then(ByteSteps.constantTimeEquals(expected))
        .run();

    expect(matches, isTrue);
    expect(CryptoBytes.encodeHex(expected), isNotEmpty);
  });
}
