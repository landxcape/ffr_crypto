## 0.0.2

### Breaking Changes

- `Random` renamed to `CryptoRandom` to avoid shadowing `dart:math`'s `Random` class.
- `Hash` renamed to `CryptoHash` to prevent conflicts with user-defined or third-party `Hash` symbols.
- `Hasher` renamed to `CryptoHasher` for consistency with the above rename.

**Migration:** find-and-replace `Random.` → `CryptoRandom.`, `Hash.` → `CryptoHash.`, `Hasher` → `CryptoHasher`.

---

## 0.0.1


Initial release of `ffr_crypto` — a Flutter-first, Rust-powered native cryptography package built on Dart FFI and Flutter Native Assets.

### Features

- **Secure Random** — CSPRNG-backed `Random.secureBytes()` for cryptographically secure byte generation.
- **RSA Asymmetric Cryptography**
  - RSA-OAEP encryption and decryption (2048, 3072, 4096-bit key sizes).
  - RSA-PSS digital signatures (signing and verification).
- **Symmetric Ciphers**
  - AES-GCM with 128-bit and 256-bit keys; supports additional authenticated data (AAD).
  - ChaCha20-Poly1305 with AAD support.
- **Hashing**
  - One-shot hashing via `Hash.hash()`: SHA-256, SHA-512, SHA3-256, SHA3-512, BLAKE3.
  - Stateful streaming hasher via `Hasher` with `update()` / `finalize()`.
  - Stream adapter `Hash.hashStream()` for hashing Dart `Stream<List<int>>` inputs.
- **Key Derivation Functions (KDFs)**
  - PBKDF2-HMAC-SHA-256.
  - HKDF-SHA-256 (extract-and-expand).
  - Argon2 (Argon2id, Argon2i, Argon2d) with configurable memory, iterations, and parallelism.
- **Elliptic Curve Cryptography**
  - Ed25519 key pair generation, signing, and verification.
  - X25519 Diffie-Hellman key exchange.
- **Hybrid Encryption (ECIES)**
  - `HybridEncryption.encrypt()` / `HybridEncryption.decrypt()` composing X25519 key agreement, HKDF-SHA-256 key derivation, and ChaCha20-Poly1305 authenticated encryption.

### Platform Support

Supports macOS, iOS, Android, Linux, and Windows via per-platform Rust cross-compilation targets. Web is not supported (`dart:ffi` is unavailable on the Web platform).

### Performance

- Expensive operations (RSA, KDFs, ECC, Hybrid Encryption) run on background Dart `Isolate`s to keep the UI thread free.
- Rust library is compiled automatically at build time via `hook/build.dart` using Flutter Native Assets.
