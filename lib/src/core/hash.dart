import 'dart:ffi' as ffi;
import 'dart:isolate';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import '../ffr_crypto_bindings_generated.dart' as bindings;
import '../native/status.dart';
import 'exceptions.dart';

// --- Hashing ---

enum HashAlgorithm { sha256, sha512, sha3_256, sha3_512, blake3 }

class CryptoHasher {
  final HashAlgorithm algorithm;
  ffi.Pointer<bindings.HasherContext> _context;
  bool _isFinalized = false;

  CryptoHasher._(this.algorithm, this._context);

  static Future<CryptoHasher> create(HashAlgorithm algorithm) async {
    final contextAddr = await Isolate.run(() async {
      final outPtr = calloc<ffi.Pointer<bindings.HasherContext>>();
      try {
        final status = bindings.ffr_crypto_hasher_new(algorithm.index, outPtr);
        checkStatus(status, 'Hasher initialization');
        return outPtr.value.address;
      } finally {
        calloc.free(outPtr);
      }
    });
    return CryptoHasher._(algorithm, ffi.Pointer.fromAddress(contextAddr));
  }

  Future<void> update(Uint8List data) async {
    if (_isFinalized) {
      throw GenericCryptoException('Hasher is already finalized');
    }
    if (_context.address == 0) {
      throw GenericCryptoException('Hasher is freed');
    }

    final contextAddress = _context.address;
    await Isolate.run(() async {
      final dataPtr = calloc<ffi.UnsignedChar>(data.length);
      dataPtr.cast<ffi.Uint8>().asTypedList(data.length).setAll(0, data);
      try {
        final status = bindings.ffr_crypto_hasher_update(
          ffi.Pointer.fromAddress(contextAddress),
          dataPtr,
          data.length,
        );
        checkStatus(status, 'Hasher update');
      } finally {
        calloc.free(dataPtr);
      }
    });
  }

  Future<Uint8List> finalize() async {
    if (_isFinalized) {
      throw GenericCryptoException('Hasher is already finalized');
    }
    if (_context.address == 0) {
      throw GenericCryptoException('Hasher is freed');
    }

    _isFinalized = true;
    final contextAddress = _context.address;

    final digest = await Isolate.run(() async {
      final outDigestPtr = calloc<ffi.Pointer<ffi.UnsignedChar>>();
      final outLenPtr = calloc<ffi.Size>();
      try {
        final status = bindings.ffr_crypto_hasher_finalize(
          ffi.Pointer.fromAddress(contextAddress),
          outDigestPtr,
          outLenPtr,
        );
        checkStatus(status, 'Hasher finalization');

        final resultLen = outLenPtr.value;
        final resultPtr = outDigestPtr.value;
        final bytes = Uint8List.fromList(
          resultPtr.cast<ffi.Uint8>().asTypedList(resultLen),
        );

        // Free Rust-allocated bytes
        bindings.ffr_crypto_free_bytes(resultPtr, resultLen);

        return bytes;
      } finally {
        calloc.free(outDigestPtr);
        calloc.free(outLenPtr);
      }
    });

    _context = ffi.Pointer.fromAddress(0);
    return digest;
  }

  void free() {
    if (!_isFinalized && _context.address != 0) {
      bindings.ffr_crypto_hasher_free(_context);
      _context = ffi.Pointer.fromAddress(0);
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
