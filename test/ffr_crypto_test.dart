import 'dart:typed_data';
import 'package:test/test.dart';
import 'package:ffr_crypto/ffr_crypto.dart';

void main() {
  group('CryptoRandom', () {
    test('secureBytes generates correct length', () async {
      final bytes = await CryptoRandom.secureBytes(32);
      expect(bytes.length, 32);
      expect(bytes, isNot(Uint8List(32))); // Assure it is not all zeros
    });

    test('secureBytes throws on invalid length', () async {
      expect(() => CryptoRandom.secureBytes(-1), throwsA(isA<CryptoException>()));
      expect(() => CryptoRandom.secureBytes(0), throwsA(isA<CryptoException>()));
    });
  });

  group('RSA Key Generation', () {
    test('generates 2048-bit keypair', () async {
      final keyPair = await RsaKeyPair.generate(2048);
      expect(keyPair.publicKey.pem, contains('BEGIN PUBLIC KEY'));
      expect(keyPair.privateKey.pem, contains('BEGIN PRIVATE KEY'));
    });

    test('throws on invalid key size', () async {
      expect(() => RsaKeyPair.generate(1024), throwsA(isA<CryptoException>()));
    });
  });

  group('RSA Encryption & Decryption', () {
    test('encrypt and decrypt match', () async {
      final keyPair = await RsaKeyPair.generate(2048);
      final plaintext = Uint8List.fromList('Hello RSA!'.codeUnits);

      final ciphertext = await Rsa.encrypt(keyPair.publicKey, plaintext);
      expect(ciphertext.length, greaterThan(0));
      expect(ciphertext, isNot(plaintext));

      final decrypted = await Rsa.decrypt(keyPair.privateKey, ciphertext);
      expect(decrypted, plaintext);
      expect(String.fromCharCodes(decrypted), 'Hello RSA!');
    });

    test('decrypt throws on corrupted ciphertext', () async {
      final keyPair = await RsaKeyPair.generate(2048);
      final corruptedCiphertext = Uint8List(
        256,
      ); // 2048 bits key yields 256 bytes ciphertext
      expect(
        () => Rsa.decrypt(keyPair.privateKey, corruptedCiphertext),
        throwsA(isA<CryptoException>()),
      );
    });
  });

  group('RSA Sign & Verify', () {
    test('sign and verify match', () async {
      final keyPair = await RsaKeyPair.generate(2048);

      // Simulating a SHA-256 digest (32 bytes)
      final digest = Uint8List.fromList(List.generate(32, (i) => i));

      final signature = await Rsa.sign(keyPair.privateKey, digest);
      expect(signature.length, 256);

      final isVerified = await Rsa.verify(keyPair.publicKey, digest, signature);
      expect(isVerified, isTrue);
    });

    test('verify returns false on modified digest/signature', () async {
      final keyPair = await RsaKeyPair.generate(2048);
      final digest = Uint8List.fromList(List.generate(32, (i) => i));
      final signature = await Rsa.sign(keyPair.privateKey, digest);

      final modifiedDigest = Uint8List.fromList(digest);
      modifiedDigest[0] ^= 1;

      final isVerified = await Rsa.verify(
        keyPair.publicKey,
        modifiedDigest,
        signature,
      );
      expect(isVerified, isFalse);
    });
  });

  group('Hashing', () {
    String toHex(Uint8List bytes) =>
        bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    test('SHA-256 known test vector', () async {
      final data = Uint8List.fromList('abc'.codeUnits);
      final digest = await CryptoHash.hash(HashAlgorithm.sha256, data);
      expect(
        toHex(digest),
        'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
      );
    });

    test('SHA-512 known test vector', () async {
      final data = Uint8List.fromList('abc'.codeUnits);
      final digest = await CryptoHash.hash(HashAlgorithm.sha512, data);
      expect(
        toHex(digest),
        'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
      );
    });

    test('SHA3-256 known test vector', () async {
      final data = Uint8List.fromList('abc'.codeUnits);
      final digest = await CryptoHash.hash(HashAlgorithm.sha3_256, data);
      expect(
        toHex(digest),
        '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532',
      );
    });

    test('BLAKE3 known test vector', () async {
      final data = Uint8List.fromList('abc'.codeUnits);
      final digest = await CryptoHash.hash(HashAlgorithm.blake3, data);
      expect(
        toHex(digest),
        '6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85',
      );
    });

    test('incremental streaming hash matches one-shot', () async {
      final chunk1 = Uint8List.fromList('hello '.codeUnits);
      final chunk2 = Uint8List.fromList('world'.codeUnits);
      final fullData = Uint8List.fromList('hello world'.codeUnits);

      final hasher = await CryptoHasher.create(HashAlgorithm.sha256);
      await hasher.update(chunk1);
      await hasher.update(chunk2);
      final streamingDigest = await hasher.finalize();

      final oneshotDigest = await CryptoHash.hash(HashAlgorithm.sha256, fullData);

      expect(streamingDigest, oneshotDigest);
    });

    test('hashStream matches one-shot', () async {
      final chunks = [
        'stream '.codeUnits,
        'hashing '.codeUnits,
        'works!'.codeUnits,
      ];
      final fullData = Uint8List.fromList(chunks.expand((x) => x).toList());

      final stream = Stream.fromIterable(chunks);
      final streamDigest = await CryptoHash.hashStream(HashAlgorithm.sha256, stream);
      final oneshotDigest = await CryptoHash.hash(HashAlgorithm.sha256, fullData);

      expect(streamDigest, oneshotDigest);
    });
  });

  group('AES-GCM Encryption & Decryption', () {
    final key128 = Uint8List(16)..setAll(0, List.generate(16, (i) => i));
    final key256 = Uint8List(32)..setAll(0, List.generate(32, (i) => i));
    final nonce = Uint8List(12)..setAll(0, List.generate(12, (i) => i + 10));
    final plaintext = Uint8List.fromList('Hello AES-GCM!'.codeUnits);
    final aad = Uint8List.fromList('some authenticated metadata'.codeUnits);

    test('AES-128-GCM encrypt and decrypt with AAD', () async {
      final ciphertext = await AesGcm.encrypt(
        key: key128,
        plaintext: plaintext,
        nonce: nonce,
        aad: aad,
      );
      expect(ciphertext.length, plaintext.length + 16); // Tag is 16 bytes

      final decrypted = await AesGcm.decrypt(
        key: key128,
        ciphertext: ciphertext,
        nonce: nonce,
        aad: aad,
      );
      expect(decrypted, plaintext);
    });

    test('AES-256-GCM encrypt and decrypt without AAD', () async {
      final ciphertext = await AesGcm.encrypt(
        key: key256,
        plaintext: plaintext,
        nonce: nonce,
      );
      expect(ciphertext.length, plaintext.length + 16);

      final decrypted = await AesGcm.decrypt(
        key: key256,
        ciphertext: ciphertext,
        nonce: nonce,
      );
      expect(decrypted, plaintext);
    });

    test('AES-GCM decryption fails with modified AAD', () async {
      final ciphertext = await AesGcm.encrypt(
        key: key256,
        plaintext: plaintext,
        nonce: nonce,
        aad: aad,
      );

      final modifiedAad = Uint8List.fromList(aad);
      modifiedAad[0] ^= 1;

      expect(
        () => AesGcm.decrypt(
          key: key256,
          ciphertext: ciphertext,
          nonce: nonce,
          aad: modifiedAad,
        ),
        throwsA(isA<CryptoException>()),
      );
    });

    test('AES-GCM decryption fails with modified ciphertext', () async {
      final ciphertext = await AesGcm.encrypt(
        key: key256,
        plaintext: plaintext,
        nonce: nonce,
      );

      final modifiedCiphertext = Uint8List.fromList(ciphertext);
      modifiedCiphertext[0] ^= 1;

      expect(
        () => AesGcm.decrypt(
          key: key256,
          ciphertext: modifiedCiphertext,
          nonce: nonce,
        ),
        throwsA(isA<CryptoException>()),
      );
    });
  });

  group('ChaCha20-Poly1305 Encryption & Decryption', () {
    final key = Uint8List(32)..setAll(0, List.generate(32, (i) => i));
    final nonce = Uint8List(12)..setAll(0, List.generate(12, (i) => i + 1));
    final plaintext = Uint8List.fromList('Hello ChaCha20-Poly1305!'.codeUnits);
    final aad = Uint8List.fromList('metadata'.codeUnits);

    test('ChaCha20-Poly1305 encrypt and decrypt with AAD', () async {
      final ciphertext = await ChaCha20Poly1305.encrypt(
        key: key,
        plaintext: plaintext,
        nonce: nonce,
        aad: aad,
      );
      expect(ciphertext.length, plaintext.length + 16);

      final decrypted = await ChaCha20Poly1305.decrypt(
        key: key,
        ciphertext: ciphertext,
        nonce: nonce,
        aad: aad,
      );
      expect(decrypted, plaintext);
    });

    test('ChaCha20-Poly1305 decryption fails with wrong key', () async {
      final ciphertext = await ChaCha20Poly1305.encrypt(
        key: key,
        plaintext: plaintext,
        nonce: nonce,
      );

      final wrongKey = Uint8List.fromList(key);
      wrongKey[0] ^= 1;

      expect(
        () => ChaCha20Poly1305.decrypt(
          key: wrongKey,
          ciphertext: ciphertext,
          nonce: nonce,
        ),
        throwsA(isA<CryptoException>()),
      );
    });
  });

  group('Key Derivation Functions (KDFs)', () {
    String toHex(Uint8List bytes) =>
        bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    test('PBKDF2 SHA-256 derivation matches target length', () async {
      final password = Uint8List.fromList('password'.codeUnits);
      final salt = Uint8List.fromList('salt'.codeUnits);
      final key = await Pbkdf2.deriveKey(
        password: password,
        salt: salt,
        iterations: 1000,
        keyLength: 32,
      );
      expect(key.length, 32);
      expect(toHex(key), isNot(contains('00000000')));
    });

    test('HKDF SHA-256 extract and expand key derivation', () async {
      final ikm = Uint8List.fromList('input_keying_material'.codeUnits);
      final salt = Uint8List.fromList('hkdf_salt'.codeUnits);
      final info = Uint8List.fromList('hkdf_info'.codeUnits);
      final key = await Hkdf.deriveKey(
        ikm: ikm,
        salt: salt,
        info: info,
        keyLength: 32,
      );
      expect(key.length, 32);
    });

    test('Argon2id derivation matches target length', () async {
      final password = Uint8List.fromList('argon2_password'.codeUnits);
      final salt = Uint8List.fromList(
        'argon2_salt_12345'.codeUnits,
      ); // Salt must be at least 8 bytes for Argon2
      final key = await Argon2.deriveKey(
        password: password,
        salt: salt,
        keyLength: 32,
        mCost: 4096, // Smaller cost for fast unit tests
        tCost: 2,
        pCost: 1,
        variant: Argon2Variant.id,
      );
      expect(key.length, 32);
      expect(toHex(key), isNot(contains('00000000')));
    });
  });

  group('Ed25519 Signing & Verification', () {
    test('generate keypair, sign, and verify signature', () async {
      final keyPair = await Ed25519.generateKeyPair();
      expect(keyPair.privateKey.length, 32);
      expect(keyPair.publicKey.length, 32);

      final message = Uint8List.fromList('Hello Ed25519!'.codeUnits);
      final signature = await Ed25519.sign(
        privateKey: keyPair.privateKey,
        message: message,
      );
      expect(signature.length, 64);

      final isVerified = await Ed25519.verify(
        publicKey: keyPair.publicKey,
        message: message,
        signature: signature,
      );
      expect(isVerified, isTrue);
    });

    test('verification fails on modified message', () async {
      final keyPair = await Ed25519.generateKeyPair();
      final message = Uint8List.fromList('Hello Ed25519!'.codeUnits);
      final signature = await Ed25519.sign(
        privateKey: keyPair.privateKey,
        message: message,
      );

      final modifiedMessage = Uint8List.fromList(message);
      modifiedMessage[0] ^= 1;

      final isVerified = await Ed25519.verify(
        publicKey: keyPair.publicKey,
        message: modifiedMessage,
        signature: signature,
      );
      expect(isVerified, isFalse);
    });
  });

  group('X25519 Diffie-Hellman Key Exchange', () {
    test('derived shared secrets match', () async {
      final alice = await X25519.generateKeyPair();
      final bob = await X25519.generateKeyPair();

      expect(alice.privateKey.length, 32);
      expect(alice.publicKey.length, 32);
      expect(bob.privateKey.length, 32);
      expect(bob.publicKey.length, 32);

      final aliceSecret = await X25519.computeSharedSecret(
        privateKey: alice.privateKey,
        peerPublicKey: bob.publicKey,
      );
      final bobSecret = await X25519.computeSharedSecret(
        privateKey: bob.privateKey,
        peerPublicKey: alice.publicKey,
      );

      expect(aliceSecret.length, 32);
      expect(bobSecret.length, 32);
      expect(aliceSecret, bobSecret);
    });
  });

  group('Hybrid Encryption (ECIES)', () {
    test('encrypt and decrypt plaintext message successfully', () async {
      final recipientKeyPair = await X25519.generateKeyPair();
      final plaintext = Uint8List.fromList(
        'Hello Hybrid Encryption World!'.codeUnits,
      );

      final payload = await HybridEncryption.encrypt(
        recipientPublicKey: recipientKeyPair.publicKey,
        plaintext: plaintext,
      );

      // Ephemeral Pubkey (32) + Encrypted plaintext + Tag (16)
      expect(payload.length, 32 + plaintext.length + 16);

      final decrypted = await HybridEncryption.decrypt(
        recipientPrivateKey: recipientKeyPair.privateKey,
        payload: payload,
      );

      expect(decrypted, plaintext);
      expect(String.fromCharCodes(decrypted), 'Hello Hybrid Encryption World!');
    });

    test('decryption fails with corrupted payload', () async {
      final recipientKeyPair = await X25519.generateKeyPair();
      final plaintext = Uint8List.fromList('secret data'.codeUnits);

      final payload = await HybridEncryption.encrypt(
        recipientPublicKey: recipientKeyPair.publicKey,
        plaintext: plaintext,
      );

      final corruptedPayload = Uint8List.fromList(payload);
      corruptedPayload[corruptedPayload.length - 1] ^=
          1; // Corrupt authentication tag

      expect(
        () => HybridEncryption.decrypt(
          recipientPrivateKey: recipientKeyPair.privateKey,
          payload: corruptedPayload,
        ),
        throwsA(isA<CryptoException>()),
      );
    });
  });
}
