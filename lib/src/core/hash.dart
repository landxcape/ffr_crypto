import 'dart:typed_data';

import '../bridge/crypto_bridge.dart';
import 'exceptions.dart';

// --- Hashing ---

enum HashAlgorithm { sha256, sha512, sha3_256, sha3_512, blake3 }

class CryptoHasher {
  final HashAlgorithm algorithm;
  int _handle;
  bool _isFinalized = false;

  CryptoHasher._(this.algorithm, this._handle);

  static Future<CryptoHasher> create(HashAlgorithm algorithm) async {
    final handle = await CryptoBridge.instance.hasherNew(algorithm.index);
    return CryptoHasher._(algorithm, handle);
  }

  Future<void> update(Uint8List data) async {
    if (_isFinalized) {
      throw GenericCryptoException('Hasher is already finalized');
    }
    if (_handle == 0) {
      throw GenericCryptoException('Hasher is freed');
    }

    await CryptoBridge.instance.hasherUpdate(_handle, data);
  }

  Future<Uint8List> finalize() async {
    if (_isFinalized) {
      throw GenericCryptoException('Hasher is already finalized');
    }
    if (_handle == 0) {
      throw GenericCryptoException('Hasher is freed');
    }

    _isFinalized = true;
    final digest = await CryptoBridge.instance.hasherFinalize(_handle);
    _handle = 0;
    return digest;
  }

  void free() {
    if (!_isFinalized && _handle != 0) {
      CryptoBridge.instance.hasherFree(_handle);
      _handle = 0;
    }
  }
}

class CryptoHash {
  /// One-shot hash helper.
  static Future<Uint8List> hash(HashAlgorithm algorithm, Uint8List data) async {
    final hasher = await CryptoHasher.create(algorithm);
    try {
      await hasher.update(data);
      return await hasher.finalize();
    } catch (e) {
      hasher.free();
      rethrow;
    }
  }

  /// Hash helper that streams chunks of a Dart Stream.
  static Future<Uint8List> hashStream(
    HashAlgorithm algorithm,
    Stream<List<int>> stream,
  ) async {
    final hasher = await CryptoHasher.create(algorithm);
    try {
      await for (final chunk in stream) {
        await hasher.update(Uint8List.fromList(chunk));
      }
      return await hasher.finalize();
    } catch (e) {
      hasher.free();
      rethrow;
    }
  }
}
