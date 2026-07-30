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
- **Advanced Compatibility Primitives:** Strict byte utilities and validated RSA PKCS#1 v1.5 block-type-1 public recovery.
- **Typed Workflows:** Optional immutable, single-use pipelines with analyzer-checked step types, explicit custom boundaries, cancellation, and contextual errors.

## Performance & Design
- **Off-Thread Processing:** All computationally expensive operations (RSA, KDFs, Hybrid, Signatures) run asynchronously on background Dart Isolates (`Isolate.run`), preventing UI frames from dropping.
- **Native Assets Pipeline:** Uses modern Flutter native assets build hooks (`hook/build.dart`) to compile the underlying Rust library automatically.
- **Robust Error Handling:** Translates C-ABI status codes into clear, typed `CryptoException` subclasses.

---

## Platform Support

`ffr_crypto` compiles a native Rust library at build time via Flutter Native Assets. It works on all platforms where a Rust toolchain is available.

| Platform | Architectures | Supported |
|----------|---------------|-----------|
| 🍎 macOS | arm64, x64 | ✅ |
| 📱 iOS | arm64, x64 (simulator) | ✅ |
| 🤖 Android | arm64-v8a, armeabi-v7a, x86, x86_64 | ✅ |
| 🐧 Linux | arm64, x64 | ✅ |
| 🪟 Windows | x64 | ✅ |
| 🌐 Web | — | ❌ (dart:ffi is unsupported on Web) |

---

## Getting Started

Add the package dependency to your `pubspec.yaml`:

```yaml
dependencies:
  ffr_crypto: ^0.0.4
```

### Choose explicit package layers

`ffr_crypto` has three isolated entrypoints. Import every layer your code uses:

```dart
import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_primitives.dart';
import 'package:ffr_crypto/ffr_crypto_flow.dart';
```

- `ffr_crypto.dart` contains the existing safe, high-level API. Existing users do not need to change imports or call sites.
- `ffr_crypto_primitives.dart` contains advanced direct primitives and strict byte utilities. It does not re-export the core library.
- `ffr_crypto_flow.dart` contains flow lifecycle, sources, steps, cancellation, and flow errors. It does not re-export either other layer.

Importing multiple entrypoints does not duplicate native assets, types, or runtime work.

### Prerequisites — Rust Toolchain

Install the [Rust toolchain](https://rustup.rs) first, then add the targets for each platform you intend to build:

```bash
# macOS (Apple Silicon + Intel)
rustup target add aarch64-apple-darwin x86_64-apple-darwin

# iOS (Device + Simulator)
rustup target add aarch64-apple-ios x86_64-apple-ios

# Android (requires NDK via Android Studio or sdkmanager)
rustup target add aarch64-linux-android armv7-linux-androideabi \
                   i686-linux-android x86_64-linux-android

# Linux
rustup target add aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu

# Windows (run on a Windows host)
rustup target add x86_64-pc-windows-msvc
```

> **Note:** Android builds additionally require the [Android NDK](https://developer.android.com/ndk). Install it via Android Studio → SDK Manager → SDK Tools → NDK.

---

## API Usage Examples

### 1. Cryptographically Secure Random Bytes
```dart
import 'package:ffr_crypto/ffr_crypto.dart';

Uint8List bytes = await CryptoRandom.secureBytes(32);
```

### 2. Hashing (One-shot & Streaming)
```dart
import 'package:ffr_crypto/ffr_crypto.dart';

// One-shot
Uint8List sha256Digest = await CryptoHash.hash(HashAlgorithm.sha256, bytes);

// Incremental/Streaming
final hasher = await CryptoHasher.create(HashAlgorithm.blake3);
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

### 7. Safe Resource Management (Streaming)
Since `CryptoHasher` retains a native pointer in Rust memory, you must ensure that memory is freed. Calling `finalize()` automatically releases the native resources, but if an error occurs beforehand, you must catch the error and free it manually:

```dart
import 'package:ffr_crypto/ffr_crypto.dart';

final hasher = await CryptoHasher.create(HashAlgorithm.blake3);
try {
  await hasher.update(chunk1);
  await hasher.update(chunk2);
  
  // finalize() automatically cleans up native memory context
  final digest = await hasher.finalize(); 
} catch (e) {
  // Free native resource if hash finalize was never reached
  hasher.free(); 
  rethrow;
}
```

### 8. Exception Handling
All cryptographic and memory status boundaries throw specific exceptions subclassed from `CryptoException`:

```dart
import 'package:ffr_crypto/ffr_crypto.dart';

try {
  final decrypted = await AesGcm.decrypt(
    key: key,
    ciphertext: manipulatedCiphertext,
    nonce: nonce,
  );
} on DecryptionException catch (e) {
  // Thrown if integrity check (AEAD tag) fails
  print('Decryption failed: Integrity check error.');
} on InvalidKeyException catch (e) {
  print('Decryption failed: Key is invalid.');
} on CryptoException catch (e) {
  print('An unexpected cryptographic error occurred: ${e.message}');
}
```

## Advanced Compatibility Primitives

`RsaPkcs1v15.publicRecover` applies the RSA public operation, validates the complete PKCS#1 v1.5 block-type-1 encoding, and returns only its non-empty payload:

```dart
import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_primitives.dart';

Future<Uint8List> recoverCompatibilityPayload(
  RsaPublicKey publicKey,
  Uint8List transformedBlock,
) {
  return RsaPkcs1v15.publicRecover(publicKey, transformedBlock);
}
```

This is payload recovery for compatibility protocols. It is not standard RSASSA-PKCS1-v1_5 verification and it does not decide what the recovered payload means. Standard RSASSA-PKCS1-v1_5 includes an ASN.1 `DigestInfo`; raw recovered payloads do not. Existing `Rsa.sign` and `Rsa.verify` remain RSA-PSS with SHA-256 digests.

`CryptoBytes` provides strict hexadecimal and canonical padded standard Base64 conversion. It rejects whitespace, prefixes, URL-safe Base64, implicit unpadded Base64, and noncanonical encodings. Equal-length `constantTimeEquals` calls Rust's `subtle` comparison; different public lengths return `false`. Input lengths are not secret, and correctness tests do not prove physical timing behavior.

## Typed Crypto Flows

Flows make linear byte transformations explicit while leaving direct APIs available:

```dart
import 'dart:typed_data';

import 'package:ffr_crypto/ffr_crypto.dart';
import 'package:ffr_crypto/ffr_crypto_flow.dart';

Future<bool> validateRecoveredPayload({
  required RsaPublicKey publicKey,
  required String transformedHex,
  required Uint8List expectedPayload,
}) {
  return CryptoFlow.fromHex(transformedHex)
      .then(RsaSteps.pkcs1v15PublicRecover(publicKey))
      .then(ByteSteps.constantTimeEquals(expectedPayload))
      .run();
}
```

Adjacent step types are checked by the Dart analyzer. Step definitions are immutable and reusable, but each `CryptoFlow` object runs exactly once. Calling `then` or `thenCustom` creates a fresh independently runnable flow without consuming the original.

`thenCustom` is the explicit caller-controlled boundary. Its callback may be synchronous or asynchronous and may call Dart, FFI, platform channels, or another package. `ffr_crypto` guarantees ordering, type progression, step-context errors, cancellation checks before and after the callback, and cleanup of resources owned by the flow. It cannot guarantee the callback's security, constant-time behavior, memory wiping, internal cancellation, native execution, batching, or cleanup of resources the callback owns.

Cancellation is cooperative through `CryptoCancellationToken`. The flow checks before and after its source and every step. Active Rust work or a custom callback is allowed to finish and clean up; its result is then discarded and no later step starts. The package does not terminate isolates during native execution.

Flow failures use `CryptoFlowException`, preserving the failing step name, zero-based index, original cause, and original stack trace. Lifecycle errors and cancellation use `CryptoFlowStateException` and `CryptoFlowCancelledException` separately. Exception messages do not include keys or intermediate values.

Rust allocations are copied into Dart-owned bytes and released before a built-in operation returns. Ordinary Dart `Uint8List` memory is garbage-collected, so the package does not claim it can always be wiped. Custom callbacks own any external resources they allocate.
