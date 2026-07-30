import {
  constants,
  createHash,
  createPublicKey,
  privateEncrypt,
  publicDecrypt,
} from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';

const packageRoot = new URL('../../', import.meta.url);
const privateKey = readFileSync(
  new URL('tool/interop/test_private_key.pem', packageRoot),
  'utf8',
);
const publicKeyPem = createPublicKey(privateKey)
  .export({ type: 'spki', format: 'pem' })
  .toString();
const messageUtf8 = 'ffr_crypto generic interoperability fixture';
const payload = createHash('sha256').update(messageUtf8, 'utf8').digest();
const transformed = privateEncrypt(
  { key: privateKey, padding: constants.RSA_PKCS1_PADDING },
  payload,
);
const recovered = publicDecrypt(
  { key: publicKeyPem, padding: constants.RSA_PKCS1_PADDING },
  transformed,
);

if (!recovered.equals(payload)) {
  throw new Error('Node recovery did not reproduce the fixture payload');
}

const fixture = {
  generator: 'node',
  operation: 'RSA_PKCS1_PADDING privateEncrypt/publicDecrypt',
  publicKeyPem,
  payloadHex: payload.toString('hex'),
  transformedHex: transformed.toString('hex'),
  expectedRecoveredHex: recovered.toString('hex'),
  messageUtf8,
  command: 'node tool/interop/generate_node_public_recovery.mjs',
  nodeVersion: process.version,
  opensslVersion: process.versions.openssl,
};

writeFileSync(
  new URL('test/fixtures/rsa_interop/node_public_recovery.json', packageRoot),
  `${JSON.stringify(fixture, null, 2)}\n`,
);
