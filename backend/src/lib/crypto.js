'use strict';

/**
 * AES-256-GCM encryption helpers.
 *
 * The ENCRYPTION_KEY env var must be a 64-character hex string (32 bytes).
 * Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 *
 * Key rotation:
 *   1. Set ENCRYPTION_KEY to the new key.
 *   2. Set ENCRYPTION_KEY_PREV to the old key.
 *   3. New messages are encrypted with ENCRYPTION_KEY.
 *   4. Old messages (encrypted with the previous key) are decrypted via
 *      ENCRYPTION_KEY_PREV as a fallback. Because messages auto-delete
 *      after 30 minutes, all old-key ciphertext is gone within half an hour.
 *   5. After 30 minutes, remove ENCRYPTION_KEY_PREV.
 *
 * All values stored in the database are base64-encoded.
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const IV_BYTES = 12;   // 96-bit IV recommended for GCM
const TAG_BYTES = 16;  // 128-bit auth tag

function getKey() {
  const hex = process.env.ENCRYPTION_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('ENCRYPTION_KEY must be a 64-character hex string (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
}

function getPrevKey() {
  const hex = process.env.ENCRYPTION_KEY_PREV;
  if (!hex) return null;
  if (hex.length !== 64) {
    throw new Error('ENCRYPTION_KEY_PREV must be a 64-character hex string (32 bytes)');
  }
  return Buffer.from(hex, 'hex');
}

/**
 * Encrypts a plaintext string.
 * @param {string} plaintext
 * @returns {{ encryptedContent: string, iv: string, authTag: string }}
 *   All values are base64-encoded strings safe to store in the database.
 */
function encrypt(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });

  const encrypted = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();

  return {
    encryptedContent: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
  };
}

/**
 * Decrypts a previously encrypted message.
 * @param {{ encryptedContent: string, iv: string, authTag: string }} params
 * @returns {string} plaintext
 */
function decryptWithKey(key, encryptedContent, iv, authTag) {
  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, 'base64'),
    { authTagLength: TAG_BYTES },
  );
  decipher.setAuthTag(Buffer.from(authTag, 'base64'));
  return Buffer.concat([
    decipher.update(Buffer.from(encryptedContent, 'base64')),
    decipher.final(),
  ]).toString('utf8');
}

function decrypt({ encryptedContent, iv, authTag }) {
  // Try the current key first
  try {
    return decryptWithKey(getKey(), encryptedContent, iv, authTag);
  } catch {
    // Fall back to the previous key if set (used during key rotation)
    const prevKey = getPrevKey();
    if (!prevKey) throw new Error('Decryption failed and no ENCRYPTION_KEY_PREV is set');
    return decryptWithKey(prevKey, encryptedContent, iv, authTag);
  }
}

module.exports = { encrypt, decrypt };
