# ffr_crypto example

A Flutter dashboard demonstrating the package's core high-level API.

The example includes:

- Cryptographically secure random bytes.
- SHA-256, SHA3-256, and BLAKE3 hashing.
- RSA key generation and RSA-OAEP encryption/decryption.
- Ed25519 key generation, signing, and verification.

Advanced primitives and typed workflows are documented in the package
[README](../README.md); this application intentionally focuses on the stable
`ffr_crypto.dart` entrypoint.

## Run the example

Install a Rust toolchain and the target required by your native platform, then
run:

```bash
flutter pub get
flutter run
```

Web is not supported because the package uses `dart:ffi`.
