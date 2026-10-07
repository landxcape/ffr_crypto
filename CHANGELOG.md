## 0.1.0

- **Web Platform Support:** Full Flutter Web support powered by WebAssembly (`wasm32-unknown-unknown`) and modern `dart:js_interop`. All cryptographic algorithms (AES-GCM, ChaCha20-Poly1305, RSA, SHA-2, SHA-3, BLAKE3, Argon2id, HKDF, PBKDF2, Ed25519, X25519) work identically on Web with zero parity loss.
- **Pre-Compiled Native Binaries:** Updated `hook/build.dart` to automatically resolve pre-compiled release binaries from local cache and GitHub Releases, eliminating the requirement for Flutter developers to install Rust, Cargo, or the Android NDK for standard app development.
- **Source Build Opt-In:** Retained `FFR_CRYPTO_BUILD_FROM_SOURCE=true` environment flag for package maintainers and developers compiling the native crate from source.
- **Decoupled Architecture:** Introduced `CryptoBridge` abstraction layer isolating native `dart:ffi` calls behind conditional imports (`bridge_ffi.dart` vs `bridge_wasm.dart`), enabling full pub.dev Web badge eligibility.
- **Automated CI/CD:** Added multi-platform GitHub Actions build workflow (`build_native_assets.yml`) to compile and attach release binaries across Android, iOS, macOS, Windows, Linux, and Web on release tags.
- **Platform Declarations:** Formally declared full 6-platform support (`android`, `ios`, `macos`, `linux`, `windows`, `web`) in `pubspec.yaml`.

---

## 0.0.9

- Fix macOS native library loading failure (`mis-aligned LINKEDIT string pool`) on Apple Silicon by disabling release-profile binary stripping in `Cargo.toml`.
- Configure `hook/build.dart` to explicitly pass `CARGO_PROFILE_RELEASE_STRIP=false` on macOS and iOS target builds to prevent upstream LLVM Mach-O symbol table misalignment.

---

## 0.0.8

- Update `code_assets` dependency constraint to support version 2.x and resolve pub.dev dependency analysis warnings.
- Add `.pubignore` to exclude local build caches, Rust compilation targets, and IDE configurations.

---

## 0.0.7

- Upgrade `ffigen` to 21.0.0 and regenerate native FFI bindings.
- Update Rust backend crate dependencies (`blake3`, `libc`, `rand`, `zerocopy`, etc.).
- Update Flutter and Dart package dependencies to their latest compatible versions.

---

## 0.0.6

- Fix native library loading failure on 32-bit ARM Android devices (`armeabi-v7a` / `armv7-linux-androideabi`) caused by missing `_Unwind_Resume` symbol.
- Configure Rust profiles with `panic = "abort"` to strip ARM EHABI unwinding tables and landing pads.
- Add automatic Android NDK toolchain and linker resolution in `hook/build.dart` (`CARGO_TARGET_<TRIPLE>_LINKER`, `CC`, `AR`, `PATH`, and `-C panic=abort`).

---

## 0.0.5

- Add isolated `ffr_crypto_primitives.dart` and `ffr_crypto_flow.dart` entrypoints without changing existing imports or APIs.
- Add validated RSA PKCS#1 v1.5 block-type-1 public recovery for compatibility protocols.
- Add strict hexadecimal, canonical standard Base64, and Rust-backed constant-time byte comparison utilities.
- Add immutable typed single-use flows, built-in recovery/hash/encoding/comparison steps, explicit custom callbacks, cooperative cancellation, and contextual flow errors.
- Add fixed Node and OpenSSL RSA interoperability fixtures with reproducible generators.
- Document explicit package layers, compatibility constraints, flow lifecycle, cancellation, error context, and resource ownership.

---

## 0.0.4

- Fix leftover class name references (`CryptoRandom`, `CryptoHash`, `CryptoHasher`) in the README.md usage examples.

---

## 0.0.3

- Fix class reference renames (`CryptoRandom` and `CryptoHash`) in the example application (`example/lib/main.dart`).

---

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
