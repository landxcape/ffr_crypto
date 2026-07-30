/// Advanced compatibility primitives and strict byte utilities.
///
/// This library does not re-export the high-level `ffr_crypto.dart` library.
/// Import both entrypoints when a primitive uses a core type such as an RSA
/// public key.
library;

export 'src/primitives/crypto_bytes.dart';
export 'src/primitives/exceptions.dart';
export 'src/primitives/rsa_pkcs1v15.dart';
