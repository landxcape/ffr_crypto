# ffr_crypto

A Flutter-first, Rust-powered native cryptography package using Dart FFI and Flutter Native Assets.

## Features

- **Secure Random:** CSPRNG random byte generation.
- **Asymmetric Cryptography:**
  - **RSA-OAEP** encryption/decryption (2048, 3072, 4096-bit).
  - **RSA-PSS** signatures (signing/verification).
- **Symmetric Cryptography:**
  - **AES-GCM** (128 & 256-bit keys) with AAD.
  - **ChaCha20-Poly1305** with AAD.
- **Hashing:** SHA-2 (SHA-256, SHA-512), SHA-3 (SHA3-256, SHA3-512), and BLAKE3 with one-shot and stateful streaming APIs.
- **Key Derivation (KDF):** PBKDF2-HMAC-SHA-256, HKDF-SHA-256, and Argon2 (id, i, d).
- **Elliptic Curve Cryptography (ECC):** Ed25519 signatures and X25519 Diffie-Hellman key exchange.
- **Hybrid Encryption (ECIES):** Composed hybrid encryption using X25519, HKDF-SHA-256, and ChaCha20-Poly1305.

## Performance & Design
- **Off-Thread Processing:** All computationally expensive operations (RSA, KDFs, Hybrid, Signatures) run asynchronously on background Dart Isolates (`Isolate.run`), preventing UI frames from dropping.
- **Native Assets Pipeline:** Uses modern Flutter native assets build hooks (`hook/build.dart`) to compile the underlying Rust library automatically.
- **Robust Error Handling:** Translates C-ABI status codes into clear, typed `CryptoException` subclasses.

---

## Getting Started

Add the package dependency to your `pubspec.yaml`:

```yaml
dependencies:
  ffr_crypto: ^0.0.1
```

Ensure your environment has the Rust toolchain installed:
```bash
rustup target add aarch64-apple-darwin x86_64-apple-darwin # for macOS
```

---

## API Usage Examples

### 1. Cryptographically Secure Random Bytes
```dart
import 'package:ffr_crypto/ffr_crypto.dart';

Uint8List bytes = await Random.secureBytes(32);
```

### 2. Hashing (One-shot & Streaming)
```dart
import 'package:ffr_crypto/ffr_crypto.dart';

// One-shot
Uint8List sha256Digest = await Hash.hash(HashAlgorithm.sha256, bytes);

// Incremental/Streaming
final hasher = await Hasher.create(HashAlgorithm.blake3);
await hasher.update(chunk1);
await hasher.update(chunk2);
Uint8List blake3Digest = await hasher.finalize(); // Context is automatically freed
```

### 3. Symmetric Encryption (AES-GCM)
```dart
import 'package:ffr_crypto/ffr_crypto.dart';

Uint8List ciphertext = await AesGcm.encrypt(
  key: key256,
  plaintext: plaintext,
  nonce: nonce12,
  aad: optionalAad,
);

Uint8List decrypted = await AesGcm.decrypt(
  key: key256,
  ciphertext: ciphertext,
  nonce: nonce12,
  aad: optionalAad,
);
```

### 4. Asymmetric Cryptography (RSA-OAEP & RSA-PSS)
```dart
import 'package:ffr_crypto/ffr_crypto.dart';

// Generate key pair
RsaKeyPair pair = await RsaKeyPair.generate(2048);

// Encrypt & Decrypt
Uint8List ciphertext = await Rsa.encrypt(pair.publicKey, plaintext);
Uint8List decrypted = await Rsa.decrypt(pair.privateKey, ciphertext);

// Sign & Verify
Uint8List sig = await Rsa.sign(pair.privateKey, digest);
bool verified = await Rsa.verify(pair.publicKey, digest, sig);
```

### 5. Elliptic Curve Cryptography (ECC)
```dart
import 'package:ffr_crypto/ffr_crypto.dart';

// Ed25519 Sign/Verify
final edPair = await Ed25519.generateKeyPair();
final sig = await Ed25519.sign(privateKey: edPair.privateKey, message: msg);
final isValid = await Ed25519.verify(publicKey: edPair.publicKey, message: msg, signature: sig);

// X25519 Key Exchange
final alice = await X25519.generateKeyPair();
final bob = await X25519.generateKeyPair();
final secretAlice = await X25519.computeSharedSecret(privateKey: alice.privateKey, peerPublicKey: bob.publicKey);
```

### 6. Hybrid Encryption (ECIES)
```dart
import 'package:ffr_crypto/ffr_crypto.dart';

// Encrypt payload for recipient using their public key
Uint8List payload = await HybridEncryption.encrypt(
  recipientPublicKey: recipientPublicKey,
  plaintext: plaintext,
);

// Recipient decrypts payload using their private key
Uint8List decrypted = await HybridEncryption.decrypt(
  recipientPrivateKey: recipientPrivateKey,
  payload: payload,
);
```
