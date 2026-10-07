import 'dart:async';
import 'dart:convert';
import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';

import '../native/status.dart';
import '../primitives/exceptions.dart';
import 'crypto_bridge.dart';

@JS('WebAssembly.instantiate')
external JSPromise<JSObject> _instantiateWasm(JSAny bytes);

CryptoBridge getBridge() => BridgeWasm();

class BridgeWasm implements CryptoBridge {
  static Completer<JSObject>? _initCompleter;
  static JSObject? _wasmExports;

  static Future<JSObject> _getExports() async {
    if (_wasmExports != null) return _wasmExports!;
    if (_initCompleter != null) return _initCompleter!.future;

    _initCompleter = Completer<JSObject>();
    try {
      final global = globalContext;
      if (global.hasProperty('__FFR_CRYPTO_WASM_BYTES__'.toJS).toDart) {
        final jsBytes =
            global.getProperty('__FFR_CRYPTO_WASM_BYTES__'.toJS) as JSAny;
        final res = await _instantiateWasm(jsBytes).toDart;
        final instance = res.getProperty('instance'.toJS) as JSObject;
        _wasmExports = instance.getProperty('exports'.toJS) as JSObject;
        _initCompleter!.complete(_wasmExports!);
        return _wasmExports!;
      }

      throw StateError(
        'ffr_crypto WebAssembly module is not initialized. '
        'Provide the wasm binary to window.__FFR_CRYPTO_WASM_BYTES__ before invoking cryptographic methods on Web.',
      );
    } catch (e, st) {
      _initCompleter!.completeError(e, st);
      _initCompleter = null;
      rethrow;
    }
  }

  static void initializeWithBytes(Uint8List wasmBytes) {
    globalContext.setProperty('__FFR_CRYPTO_WASM_BYTES__'.toJS, wasmBytes.toJS);
    _wasmExports = null;
    _initCompleter = null;
  }

  static Future<int> _call(String name, [List<JSAny?>? args]) async {
    final exports = await _getExports();
    final jsFn = exports.getProperty(name.toJS) as JSFunction;
    final a = args ?? const [];
    JSAny? res;
    if (a.isEmpty) {
      res = jsFn.callAsFunction(exports);
    } else if (a.length == 1) {
      res = jsFn.callAsFunction(exports, a[0]);
    } else if (a.length == 2) {
      res = jsFn.callAsFunction(exports, a[0], a[1]);
    } else if (a.length == 3) {
      res = jsFn.callAsFunction(exports, a[0], a[1], a[2]);
    } else if (a.length == 4) {
      res = jsFn.callAsFunction(exports, a[0], a[1], a[2], a[3]);
    } else {
      final jsArray = a.toJS;
      final apply = (jsFn as JSObject).getProperty('apply'.toJS) as JSFunction;
      res = apply.callAsFunction(jsFn, exports, jsArray);
    }
    return (res as JSNumber).toDartInt;
  }

  static Future<int> _alloc(int size) async {
    return await _call('ffr_crypto_alloc', [size.toJS]);
  }

  static Future<void> _dealloc(int ptr, int size) async {
    await _call('ffr_crypto_dealloc', [ptr.toJS, size.toJS]);
  }

  static Future<Uint8List> _readMemory(int ptr, int len) async {
    final exports = await _getExports();
    final memory = exports.getProperty('memory'.toJS) as JSObject;
    final buffer = memory.getProperty('buffer'.toJS) as JSArrayBuffer;
    final view = Uint8List.view(buffer.toDart, ptr, len);
    return Uint8List.fromList(view);
  }

  static Future<void> _writeMemory(int ptr, Uint8List data) async {
    final exports = await _getExports();
    final memory = exports.getProperty('memory'.toJS) as JSObject;
    final buffer = memory.getProperty('buffer'.toJS) as JSArrayBuffer;
    final view = Uint8List.view(buffer.toDart, ptr, data.length);
    view.setAll(0, data);
  }

  @override
  Future<Uint8List> randomBytes(int length) async {
    final ptr = await _alloc(length);
    try {
      final status = await _call('ffr_crypto_random_bytes', [
        ptr.toJS,
        length.toJS,
      ]);
      checkStatus(status, 'Random generation');
      return await _readMemory(ptr, length);
    } finally {
      await _dealloc(ptr, length);
    }
  }

  @override
  Future<({String publicKeyPem, String privateKeyPem})> rsaGenerateKeypair(
    int keySize,
  ) async {
    final pubPtrPtr = await _alloc(4);
    final privPtrPtr = await _alloc(4);
    try {
      final status = await _call('ffr_crypto_rsa_generate_keypair', [
        keySize.toJS,
        pubPtrPtr.toJS,
        privPtrPtr.toJS,
      ]);
      checkStatus(status, 'RSA key generation');

      final pubPtrBytes = await _readMemory(pubPtrPtr, 4);
      final privPtrBytes = await _readMemory(privPtrPtr, 4);
      final pubPtr = pubPtrBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );
      final privPtr = privPtrBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );

      final pubStr = await _readNullTerminatedString(pubPtr);
      final privStr = await _readNullTerminatedString(privPtr);

      await _call('ffr_crypto_free_string', [pubPtr.toJS]);
      await _call('ffr_crypto_free_string', [privPtr.toJS]);

      return (publicKeyPem: pubStr, privateKeyPem: privStr);
    } finally {
      await _dealloc(pubPtrPtr, 4);
      await _dealloc(privPtrPtr, 4);
    }
  }

  static Future<String> _readNullTerminatedString(int ptr) async {
    final bytes = <int>[];
    int offset = ptr;
    while (true) {
      final b = (await _readMemory(offset, 1))[0];
      if (b == 0) break;
      bytes.add(b);
      offset++;
    }
    return utf8.decode(bytes);
  }

  @override
  Future<Uint8List> rsaEncrypt({
    required String publicKeyPem,
    required Uint8List plaintext,
  }) async {
    final pemBytes = utf8.encode('$publicKeyPem\x00');
    final pubPtr = await _alloc(pemBytes.length);
    await _writeMemory(pubPtr, Uint8List.fromList(pemBytes));

    final plainPtr = await _alloc(plaintext.length);
    await _writeMemory(plainPtr, plaintext);

    final outPtrPtr = await _alloc(4);
    final outLenPtr = await _alloc(4);

    try {
      final status = await _call('ffr_crypto_rsa_encrypt', [
        pubPtr.toJS,
        plainPtr.toJS,
        plaintext.length.toJS,
        outPtrPtr.toJS,
        outLenPtr.toJS,
      ]);
      checkStatus(status, 'RSA encryption');

      final outPtrBytes = await _readMemory(outPtrPtr, 4);
      final outLenBytes = await _readMemory(outLenPtr, 4);
      final outPtr = outPtrBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );
      final outLen = outLenBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );

      final result = await _readMemory(outPtr, outLen);
      await _call('ffr_crypto_free_bytes', [outPtr.toJS, outLen.toJS]);
      return result;
    } finally {
      await _dealloc(pubPtr, pemBytes.length);
      await _dealloc(plainPtr, plaintext.length);
      await _dealloc(outPtrPtr, 4);
      await _dealloc(outLenPtr, 4);
    }
  }

  @override
  Future<Uint8List> rsaDecrypt({
    required String privateKeyPem,
    required Uint8List ciphertext,
  }) async {
    final pemBytes = utf8.encode('$privateKeyPem\x00');
    final privPtr = await _alloc(pemBytes.length);
    await _writeMemory(privPtr, Uint8List.fromList(pemBytes));

    final cipherPtr = await _alloc(ciphertext.length);
    await _writeMemory(cipherPtr, ciphertext);

    final outPtrPtr = await _alloc(4);
    final outLenPtr = await _alloc(4);

    try {
      final status = await _call('ffr_crypto_rsa_decrypt', [
        privPtr.toJS,
        cipherPtr.toJS,
        ciphertext.length.toJS,
        outPtrPtr.toJS,
        outLenPtr.toJS,
      ]);
      checkStatus(status, 'RSA decryption');

      final outPtrBytes = await _readMemory(outPtrPtr, 4);
      final outLenBytes = await _readMemory(outLenPtr, 4);
      final outPtr = outPtrBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );
      final outLen = outLenBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );

      final result = await _readMemory(outPtr, outLen);
      await _call('ffr_crypto_free_bytes', [outPtr.toJS, outLen.toJS]);
      return result;
    } finally {
      await _dealloc(privPtr, pemBytes.length);
      await _dealloc(cipherPtr, ciphertext.length);
      await _dealloc(outPtrPtr, 4);
      await _dealloc(outLenPtr, 4);
    }
  }

  @override
  Future<Uint8List> rsaSign({
    required String privateKeyPem,
    required Uint8List digest,
  }) async {
    final pemBytes = utf8.encode('$privateKeyPem\x00');
    final privPtr = await _alloc(pemBytes.length);
    await _writeMemory(privPtr, Uint8List.fromList(pemBytes));

    final digestPtr = await _alloc(digest.length);
    await _writeMemory(digestPtr, digest);

    final outPtrPtr = await _alloc(4);
    final outLenPtr = await _alloc(4);

    try {
      final status = await _call('ffr_crypto_rsa_sign', [
        privPtr.toJS,
        digestPtr.toJS,
        digest.length.toJS,
        outPtrPtr.toJS,
        outLenPtr.toJS,
      ]);
      checkStatus(status, 'RSA signing');

      final outPtrBytes = await _readMemory(outPtrPtr, 4);
      final outLenBytes = await _readMemory(outLenPtr, 4);
      final outPtr = outPtrBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );
      final outLen = outLenBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );

      final result = await _readMemory(outPtr, outLen);
      await _call('ffr_crypto_free_bytes', [outPtr.toJS, outLen.toJS]);
      return result;
    } finally {
      await _dealloc(privPtr, pemBytes.length);
      await _dealloc(digestPtr, digest.length);
      await _dealloc(outPtrPtr, 4);
      await _dealloc(outLenPtr, 4);
    }
  }

  @override
  Future<bool> rsaVerify({
    required String publicKeyPem,
    required Uint8List digest,
    required Uint8List signature,
  }) async {
    final pemBytes = utf8.encode('$publicKeyPem\x00');
    final pubPtr = await _alloc(pemBytes.length);
    await _writeMemory(pubPtr, Uint8List.fromList(pemBytes));

    final digestPtr = await _alloc(digest.length);
    await _writeMemory(digestPtr, digest);

    final sigPtr = await _alloc(signature.length);
    await _writeMemory(sigPtr, signature);

    try {
      final status = await _call('ffr_crypto_rsa_verify', [
        pubPtr.toJS,
        digestPtr.toJS,
        digest.length.toJS,
        sigPtr.toJS,
        signature.length.toJS,
      ]);
      if (status == statusSuccess) return true;
      if (status == statusVerificationFailed) return false;
      checkStatus(status, 'RSA verification');
      return false;
    } finally {
      await _dealloc(pubPtr, pemBytes.length);
      await _dealloc(digestPtr, digest.length);
      await _dealloc(sigPtr, signature.length);
    }
  }

  @override
  Future<int> hasherNew(int algorithmId) async {
    final outPtrPtr = await _alloc(4);
    try {
      final status = await _call('ffr_crypto_hasher_new', [
        algorithmId.toJS,
        outPtrPtr.toJS,
      ]);
      checkStatus(status, 'Hasher initialization');
      final outPtrBytes = await _readMemory(outPtrPtr, 4);
      return outPtrBytes.buffer.asByteData().getUint32(0, Endian.little);
    } finally {
      await _dealloc(outPtrPtr, 4);
    }
  }

  @override
  Future<void> hasherUpdate(int hasherHandle, Uint8List data) async {
    final dataPtr = await _alloc(data.length);
    await _writeMemory(dataPtr, data);
    try {
      final status = await _call('ffr_crypto_hasher_update', [
        hasherHandle.toJS,
        dataPtr.toJS,
        data.length.toJS,
      ]);
      checkStatus(status, 'Hasher update');
    } finally {
      await _dealloc(dataPtr, data.length);
    }
  }

  @override
  Future<Uint8List> hasherFinalize(int hasherHandle) async {
    final outPtrPtr = await _alloc(4);
    final outLenPtr = await _alloc(4);
    try {
      final status = await _call('ffr_crypto_hasher_finalize', [
        hasherHandle.toJS,
        outPtrPtr.toJS,
        outLenPtr.toJS,
      ]);
      checkStatus(status, 'Hasher finalize');

      final outPtrBytes = await _readMemory(outPtrPtr, 4);
      final outLenBytes = await _readMemory(outLenPtr, 4);
      final outPtr = outPtrBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );
      final outLen = outLenBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );

      final result = await _readMemory(outPtr, outLen);
      await _call('ffr_crypto_free_bytes', [outPtr.toJS, outLen.toJS]);
      return result;
    } finally {
      await _dealloc(outPtrPtr, 4);
      await _dealloc(outLenPtr, 4);
    }
  }

  @override
  Future<void> hasherFree(int hasherHandle) async {
    await _call('ffr_crypto_hasher_free', [hasherHandle.toJS]);
  }

  @override
  Future<Uint8List> aesGcmEncrypt({
    required Uint8List key,
    required Uint8List plaintext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    return await _symmetricCipher(
      'ffr_crypto_aes_gcm_encrypt',
      'AES-GCM encryption',
      key,
      plaintext,
      nonce,
      aad,
    );
  }

  @override
  Future<Uint8List> aesGcmDecrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    return await _symmetricCipher(
      'ffr_crypto_aes_gcm_decrypt',
      'AES-GCM decryption',
      key,
      ciphertext,
      nonce,
      aad,
    );
  }

  @override
  Future<Uint8List> chacha20Poly1305Encrypt({
    required Uint8List key,
    required Uint8List plaintext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    return await _symmetricCipher(
      'ffr_crypto_chacha20_poly1305_encrypt',
      'ChaCha20-Poly1305 encryption',
      key,
      plaintext,
      nonce,
      aad,
    );
  }

  @override
  Future<Uint8List> chacha20Poly1305Decrypt({
    required Uint8List key,
    required Uint8List ciphertext,
    required Uint8List nonce,
    Uint8List? aad,
  }) async {
    return await _symmetricCipher(
      'ffr_crypto_chacha20_poly1305_decrypt',
      'ChaCha20-Poly1305 decryption',
      key,
      ciphertext,
      nonce,
      aad,
    );
  }

  Future<Uint8List> _symmetricCipher(
    String fnName,
    String desc,
    Uint8List key,
    Uint8List input,
    Uint8List nonce,
    Uint8List? aad,
  ) async {
    final keyPtr = await _alloc(key.length);
    await _writeMemory(keyPtr, key);

    final inputPtr = await _alloc(input.length);
    await _writeMemory(inputPtr, input);

    final noncePtr = await _alloc(nonce.length);
    await _writeMemory(noncePtr, nonce);

    final aadLen = aad?.length ?? 0;
    final aadPtr = aadLen > 0 ? await _alloc(aadLen) : 0;
    if (aadLen > 0) {
      await _writeMemory(aadPtr, aad!);
    }

    final outPtrPtr = await _alloc(4);
    final outLenPtr = await _alloc(4);

    try {
      final status = await _call(fnName, [
        keyPtr.toJS,
        key.length.toJS,
        inputPtr.toJS,
        input.length.toJS,
        noncePtr.toJS,
        nonce.length.toJS,
        aadPtr.toJS,
        aadLen.toJS,
        outPtrPtr.toJS,
        outLenPtr.toJS,
      ]);
      checkStatus(status, desc);

      final outPtrBytes = await _readMemory(outPtrPtr, 4);
      final outLenBytes = await _readMemory(outLenPtr, 4);
      final outPtr = outPtrBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );
      final outLen = outLenBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );

      final result = await _readMemory(outPtr, outLen);
      await _call('ffr_crypto_free_bytes', [outPtr.toJS, outLen.toJS]);
      return result;
    } finally {
      await _dealloc(keyPtr, key.length);
      await _dealloc(inputPtr, input.length);
      await _dealloc(noncePtr, nonce.length);
      if (aadLen > 0) await _dealloc(aadPtr, aadLen);
      await _dealloc(outPtrPtr, 4);
      await _dealloc(outLenPtr, 4);
    }
  }

  @override
  Future<Uint8List> pbkdf2({
    required Uint8List password,
    required Uint8List salt,
    required int iterations,
    required int outputLength,
  }) async {
    final passPtr = await _alloc(password.length);
    await _writeMemory(passPtr, password);

    final saltPtr = await _alloc(salt.length);
    await _writeMemory(saltPtr, salt);

    final outKeyPtr = await _alloc(outputLength);

    try {
      final status = await _call('ffr_crypto_pbkdf2', [
        passPtr.toJS,
        password.length.toJS,
        saltPtr.toJS,
        salt.length.toJS,
        iterations.toJS,
        outKeyPtr.toJS,
        outputLength.toJS,
      ]);
      checkStatus(status, 'PBKDF2 key derivation');
      return await _readMemory(outKeyPtr, outputLength);
    } finally {
      await _dealloc(passPtr, password.length);
      await _dealloc(saltPtr, salt.length);
      await _dealloc(outKeyPtr, outputLength);
    }
  }

  @override
  Future<Uint8List> hkdf({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    required int outputLength,
  }) async {
    final ikmPtr = await _alloc(ikm.length);
    await _writeMemory(ikmPtr, ikm);

    final saltPtr = await _alloc(salt.length);
    await _writeMemory(saltPtr, salt);

    final infoPtr = await _alloc(info.length);
    await _writeMemory(infoPtr, info);

    final outKeyPtr = await _alloc(outputLength);

    try {
      final status = await _call('ffr_crypto_hkdf', [
        ikmPtr.toJS,
        ikm.length.toJS,
        saltPtr.toJS,
        salt.length.toJS,
        infoPtr.toJS,
        info.length.toJS,
        outKeyPtr.toJS,
        outputLength.toJS,
      ]);
      checkStatus(status, 'HKDF key derivation');
      return await _readMemory(outKeyPtr, outputLength);
    } finally {
      await _dealloc(ikmPtr, ikm.length);
      await _dealloc(saltPtr, salt.length);
      await _dealloc(infoPtr, info.length);
      await _dealloc(outKeyPtr, outputLength);
    }
  }

  @override
  Future<Uint8List> argon2({
    required Uint8List password,
    required Uint8List salt,
    required int mCost,
    required int tCost,
    required int pCost,
    required int variant,
    required int outputLength,
  }) async {
    final passPtr = await _alloc(password.length);
    await _writeMemory(passPtr, password);

    final saltPtr = await _alloc(salt.length);
    await _writeMemory(saltPtr, salt);

    final outKeyPtr = await _alloc(outputLength);

    try {
      final status = await _call('ffr_crypto_argon2', [
        passPtr.toJS,
        password.length.toJS,
        saltPtr.toJS,
        salt.length.toJS,
        mCost.toJS,
        tCost.toJS,
        pCost.toJS,
        variant.toJS,
        outKeyPtr.toJS,
        outputLength.toJS,
      ]);
      checkStatus(status, 'Argon2 key derivation');
      return await _readMemory(outKeyPtr, outputLength);
    } finally {
      await _dealloc(passPtr, password.length);
      await _dealloc(saltPtr, salt.length);
      await _dealloc(outKeyPtr, outputLength);
    }
  }

  @override
  Future<({Uint8List publicKey, Uint8List privateKey})>
  ed25519GenerateKeypair() async {
    final pubPtr = await _alloc(32);
    final privPtr = await _alloc(32);
    try {
      final status = await _call('ffr_crypto_ed25519_generate_keypair', [
        pubPtr.toJS,
        privPtr.toJS,
      ]);
      checkStatus(status, 'Ed25519 key generation');
      final pub = await _readMemory(pubPtr, 32);
      final priv = await _readMemory(privPtr, 32);
      return (publicKey: pub, privateKey: priv);
    } finally {
      await _dealloc(pubPtr, 32);
      await _dealloc(privPtr, 32);
    }
  }

  @override
  Future<Uint8List> ed25519Sign({
    required Uint8List privateKey,
    required Uint8List message,
  }) async {
    final privPtr = await _alloc(32);
    await _writeMemory(privPtr, privateKey);

    final msgPtr = await _alloc(message.length);
    await _writeMemory(msgPtr, message);

    final sigPtr = await _alloc(64);

    try {
      final status = await _call('ffr_crypto_ed25519_sign', [
        privPtr.toJS,
        msgPtr.toJS,
        message.length.toJS,
        sigPtr.toJS,
      ]);
      checkStatus(status, 'Ed25519 signing');
      return await _readMemory(sigPtr, 64);
    } finally {
      await _dealloc(privPtr, 32);
      await _dealloc(msgPtr, message.length);
      await _dealloc(sigPtr, 64);
    }
  }

  @override
  Future<bool> ed25519Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) async {
    final pubPtr = await _alloc(32);
    await _writeMemory(pubPtr, publicKey);

    final msgPtr = await _alloc(message.length);
    await _writeMemory(msgPtr, message);

    final sigPtr = await _alloc(64);
    await _writeMemory(sigPtr, signature);

    try {
      final status = await _call('ffr_crypto_ed25519_verify', [
        pubPtr.toJS,
        msgPtr.toJS,
        message.length.toJS,
        sigPtr.toJS,
      ]);
      if (status == statusSuccess) return true;
      if (status == statusVerificationFailed) return false;
      checkStatus(status, 'Ed25519 verification');
      return false;
    } finally {
      await _dealloc(pubPtr, 32);
      await _dealloc(msgPtr, message.length);
      await _dealloc(sigPtr, 64);
    }
  }

  @override
  Future<({Uint8List publicKey, Uint8List privateKey})>
  x25519GenerateKeypair() async {
    final pubPtr = await _alloc(32);
    final privPtr = await _alloc(32);
    try {
      final status = await _call('ffr_crypto_x25519_generate_keypair', [
        pubPtr.toJS,
        privPtr.toJS,
      ]);
      checkStatus(status, 'X25519 key generation');
      final pub = await _readMemory(pubPtr, 32);
      final priv = await _readMemory(privPtr, 32);
      return (publicKey: pub, privateKey: priv);
    } finally {
      await _dealloc(pubPtr, 32);
      await _dealloc(privPtr, 32);
    }
  }

  @override
  Future<Uint8List> x25519ComputeSharedSecret({
    required Uint8List privateKey,
    required Uint8List peerPublicKey,
  }) async {
    final privPtr = await _alloc(32);
    await _writeMemory(privPtr, privateKey);

    final peerPtr = await _alloc(32);
    await _writeMemory(peerPtr, peerPublicKey);

    final outPtr = await _alloc(32);

    try {
      final status = await _call('ffr_crypto_x25519_compute_shared_secret', [
        privPtr.toJS,
        peerPtr.toJS,
        outPtr.toJS,
      ]);
      checkStatus(status, 'X25519 shared secret');
      return await _readMemory(outPtr, 32);
    } finally {
      await _dealloc(privPtr, 32);
      await _dealloc(peerPtr, 32);
      await _dealloc(outPtr, 32);
    }
  }

  @override
  Future<bool> constantTimeEquals({
    required Uint8List left,
    required Uint8List right,
  }) async {
    final leftPtr = await _alloc(left.length);
    await _writeMemory(leftPtr, left);

    final rightPtr = await _alloc(right.length);
    await _writeMemory(rightPtr, right);

    final outEqual = await _alloc(1);

    try {
      final status = await _call('ffr_crypto_constant_time_equals', [
        leftPtr.toJS,
        left.length.toJS,
        rightPtr.toJS,
        right.length.toJS,
        outEqual.toJS,
      ]);
      checkStatus(status, 'Constant-time comparison');
      final res = await _readMemory(outEqual, 1);
      return res[0] != 0;
    } finally {
      await _dealloc(leftPtr, left.length);
      await _dealloc(rightPtr, right.length);
      await _dealloc(outEqual, 1);
    }
  }

  @override
  Future<Uint8List> rsaPkcs1v15PublicRecover({
    required String publicKeyPem,
    required Uint8List input,
  }) async {
    final pemBytes = utf8.encode('$publicKeyPem\x00');
    final pubPtr = await _alloc(pemBytes.length);
    await _writeMemory(pubPtr, Uint8List.fromList(pemBytes));

    final inPtr = await _alloc(input.length);
    await _writeMemory(inPtr, input);

    final outPtrPtr = await _alloc(4);
    final outLenPtr = await _alloc(4);

    try {
      final status = await _call('ffr_crypto_rsa_pkcs1v15_public_recover', [
        pubPtr.toJS,
        inPtr.toJS,
        input.length.toJS,
        outPtrPtr.toJS,
        outLenPtr.toJS,
      ]);
      switch (status) {
        case statusSuccess:
          break;
        case statusRsaRecoveryFailed:
          throw RsaRecoveryException('RSA PKCS#1 v1.5 public recovery failed');
        default:
          checkStatus(status, 'RSA PKCS#1 v1.5 public recovery');
      }

      final outPtrBytes = await _readMemory(outPtrPtr, 4);
      final outLenBytes = await _readMemory(outLenPtr, 4);
      final outPtr = outPtrBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );
      final outLen = outLenBytes.buffer.asByteData().getUint32(
        0,
        Endian.little,
      );

      final result = await _readMemory(outPtr, outLen);
      await _call('ffr_crypto_free_bytes', [outPtr.toJS, outLen.toJS]);
      return result;
    } finally {
      await _dealloc(pubPtr, pemBytes.length);
      await _dealloc(inPtr, input.length);
      await _dealloc(outPtrPtr, 4);
      await _dealloc(outLenPtr, 4);
    }
  }
}
