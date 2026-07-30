#!/bin/sh
set -eu

PACKAGE_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
PRIVATE_KEY="$PACKAGE_ROOT/tool/interop/test_private_key.pem"
OUTPUT="$PACKAGE_ROOT/test/fixtures/rsa_interop/openssl_pss_sha256.json"
MESSAGE='ffr_crypto generic interoperability fixture'
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT HUP INT TERM

printf '%s' "$MESSAGE" > "$TEMP_DIR/message.bin"
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$TEMP_DIR/public.pem"
openssl dgst -sha256 -binary -out "$TEMP_DIR/digest.bin" "$TEMP_DIR/message.bin"
openssl dgst -sha256 \
  -sign "$PRIVATE_KEY" \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_mgf1_md:sha256 \
  -sigopt rsa_pss_saltlen:digest \
  -out "$TEMP_DIR/signature.bin" \
  "$TEMP_DIR/message.bin"
openssl dgst -sha256 \
  -verify "$TEMP_DIR/public.pem" \
  -signature "$TEMP_DIR/signature.bin" \
  -sigopt rsa_padding_mode:pss \
  -sigopt rsa_mgf1_md:sha256 \
  -sigopt rsa_pss_saltlen:digest \
  "$TEMP_DIR/message.bin"

PUBLIC_PATH="$TEMP_DIR/public.pem" \
MESSAGE_PATH="$TEMP_DIR/message.bin" \
DIGEST_PATH="$TEMP_DIR/digest.bin" \
SIGNATURE_PATH="$TEMP_DIR/signature.bin" \
OUTPUT_PATH="$OUTPUT" \
OPENSSL_VERSION="$(openssl version)" \
node --input-type=module -e '
  import { readFileSync, writeFileSync } from "node:fs";
  const hex = (path) => readFileSync(path).toString("hex");
  const fixture = {
    generator: "openssl",
    operation: "RSA-PSS SHA-256 with MGF1-SHA-256 and digest-sized salt",
    publicKeyPem: readFileSync(process.env.PUBLIC_PATH, "utf8"),
    messageUtf8: readFileSync(process.env.MESSAGE_PATH, "utf8"),
    messageHex: hex(process.env.MESSAGE_PATH),
    digestHex: hex(process.env.DIGEST_PATH),
    signatureHex: hex(process.env.SIGNATURE_PATH),
    paddingMode: "pss",
    mgf1Hash: "sha256",
    saltLength: "digest",
    generatorCommand: "sh tool/interop/generate_openssl_pss.sh",
    signingCommand: "openssl dgst -sha256 -sign tool/interop/test_private_key.pem -sigopt rsa_padding_mode:pss -sigopt rsa_mgf1_md:sha256 -sigopt rsa_pss_saltlen:digest",
    opensslVersion: process.env.OPENSSL_VERSION,
  };
  writeFileSync(process.env.OUTPUT_PATH, `${JSON.stringify(fixture, null, 2)}\n`);
'
