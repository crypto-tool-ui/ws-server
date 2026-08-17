/**
 * E2E Encryption — mirrors the Rust crypto.rs module.
 * Uses Node.js native X25519 via JWK format.
 */

const crypto = require('crypto');
const HKDF_SALT = Buffer.from('csd-pool-e2e-v1');
const HKDF_INFO = Buffer.from('aes-256-gcm-key');

/** Import raw 32-byte public key as a KeyObject (JWK format) */
function pubKeyObj(raw) {
  return crypto.createPublicKey({
    key: { kty: 'OKP', crv: 'X25519', x: raw.toString('base64url') },
    format: 'jwk',
  });
}

function generateKeypair() {
  const kp = crypto.generateKeyPairSync('x25519');
  return {
    privateKeyObj: kp.privateKey,
    publicKey: kp.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32),
  };
}

function ecdh(privateKeyObj, peerPublicKeyRaw) {
  return crypto.diffieHellman({ privateKey: privateKeyObj, publicKey: pubKeyObj(peerPublicKeyRaw) });
}

function derivePublicKey(privateKeyObj) {
  return crypto.createPublicKey(privateKeyObj)
    .export({ type: 'spki', format: 'der' }).subarray(-32);
}

function deriveKey(sharedSecret) {
  return crypto.hkdfSync('sha256', sharedSecret, HKDF_SALT, HKDF_INFO, 32);
}

function buildNonce(counter) {
  const nonce = Buffer.alloc(12);
  nonce.write('CSD!', 0, 'ascii');
  nonce.writeBigUInt64BE(BigInt(counter), 4);
  return nonce;
}

function createSession(sharedSecret) {
  const aesKey = deriveKey(sharedSecret);
  let counter = 0;
  return {
    encrypt(plaintext) {
      counter++;
      const nonce = buildNonce(counter);
      const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, nonce, { authTagLength: 16 });
      const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();
      const wire = Buffer.alloc(1 + nonce.length + enc.length + tag.length);
      wire[0] = nonce.length;
      nonce.copy(wire, 1);
      enc.copy(wire, 1 + nonce.length);
      tag.copy(wire, 1 + nonce.length + enc.length);
      return wire;
    },
    decrypt(wire) {
      if (wire.length < 1 + 16 + 1) throw new Error('E2E decrypt: frame too short');
      const nLen = wire[0];
      if (wire.length < 1 + nLen + 16) throw new Error('E2E decrypt: frame too short');
      const nonce = wire.subarray(1, 1 + nLen);
      const ct = wire.subarray(1 + nLen);
      const d = crypto.createDecipheriv('aes-256-gcm', aesKey, nonce, { authTagLength: 16 });
      d.setAuthTag(ct.subarray(ct.length - 16));
      return Buffer.concat([d.update(ct.subarray(0, ct.length - 16)), d.final()]);
    },
  };
}

module.exports = { generateKeypair, ecdh, derivePublicKey, createSession };
