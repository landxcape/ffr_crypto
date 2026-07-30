import 'dart:typed_data';

import 'aead.dart';
import 'ecc.dart';
import 'exceptions.dart';
import 'kdf.dart';

// --- Hybrid Encryption ---

class HybridEncryption {
  /// Encrypts a [plaintext] message for a recipient identified by their X25519 [recipientPublicKey].
  /// Returns a packaged payload containing: Ephemeral Public Key (32 bytes) + Ciphertext + Tag (16 bytes).
  static Future<Uint8List> encrypt({
    required Uint8List recipientPublicKey,
    required Uint8List plaintext,
  }) async {
    if (recipientPublicKey.length != 32) {
      throw InvalidKeyException('Recipient public key must be 32 bytes');
    }

    // 1. Generate ephemeral key pair
    final ephemeral = await X25519.generateKeyPair();

    // 2. Compute shared secret
    final sharedSecret = await X25519.computeSharedSecret(
      privateKey: ephemeral.privateKey,
      peerPublicKey: recipientPublicKey,
    );

    // 3. Derive symmetric key (32 bytes) and nonce (12 bytes) using HKDF
    final derived = await Hkdf.deriveKey(
      ikm: sharedSecret,
      salt: Uint8List(0),
      info: ephemeral.publicKey,
      keyLength: 44, // 32 bytes key + 12 bytes nonce
    );

    final symKey = derived.sublist(0, 32);
    final nonce = derived.sublist(32, 44);

    // 4. Encrypt using ChaCha20-Poly1305
    final ciphertext = await ChaCha20Poly1305.encrypt(
      key: symKey,
      plaintext: plaintext,
      nonce: nonce,
    );

    // 5. Package output: Ephemeral Pubkey (32 bytes) + Ciphertext
    final payload = BytesBuilder();
    payload.add(ephemeral.publicKey);
    payload.add(ciphertext);
    return payload.toBytes();
  }

  /// Decrypts a packaged hybrid encryption payload using the recipient's X25519 [recipientPrivateKey].
  static Future<Uint8List> decrypt({
    required Uint8List recipientPrivateKey,
    required Uint8List payload,
  }) async {
    if (recipientPrivateKey.length != 32) {
      throw InvalidKeyException('Recipient private key must be 32 bytes');
    }
    if (payload.length < 48) {
      // 32 bytes (pubkey) + 16 bytes (tag minimum)
      throw InvalidInputException('Invalid hybrid encryption payload size');
    }

    // 1. Extract ephemeral pubkey and ciphertext
    final ephemeralPublicKey = payload.sublist(0, 32);
    final ciphertext = payload.sublist(32);

    // 2. Compute shared secret
    final sharedSecret = await X25519.computeSharedSecret(
      privateKey: recipientPrivateKey,
      peerPublicKey: ephemeralPublicKey,
    );

    // 3. Derive symmetric key and nonce using HKDF
    final derived = await Hkdf.deriveKey(
      ikm: sharedSecret,
      salt: Uint8List(0),
      info: ephemeralPublicKey,
      keyLength: 44,
    );

    final symKey = derived.sublist(0, 32);
    final nonce = derived.sublist(32, 44);

    // 4. Decrypt using ChaCha20-Poly1305
    return await ChaCha20Poly1305.decrypt(
      key: symKey,
      ciphertext: ciphertext,
      nonce: nonce,
    );
  }
}
