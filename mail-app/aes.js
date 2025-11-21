// aes.js
// AES-256-CBC helper: random IV per encryption, return iv + ciphertext in hex.
// Read AES key from environment variable AES_KEY (hex, 64 chars). If not set,
// a random key will be used for demo only (do NOT commit that to git in production).

const crypto = require('crypto');

let AES_KEY;
if (process.env.AES_KEY) {
  // AES_KEY must be provided as hex sequence (64 hex chars => 32 bytes)
  AES_KEY = Buffer.from(process.env.AES_KEY, 'hex');
  if (AES_KEY.length !== 32) {
    throw new Error('AES_KEY environment variable must be 32 bytes (64 hex chars).');
  }
} else {
  // Demo fallback - generate a random key. For real deployments set AES_KEY env var.
  AES_KEY = crypto.randomBytes(32);
  console.warn('⚠️ AES_KEY not set. Using a random key for this run (do NOT commit).');
}

function encrypt(plainText) {
  const iv = crypto.randomBytes(16); // 128-bit IV for CBC
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  const ciphertext = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()]);
  return {
    iv: iv.toString('hex'),
    ciphertext: ciphertext.toString('hex')
  };
}

function decrypt({ iv, ciphertext }) {
  if (!iv || !ciphertext) throw new Error('Missing iv or ciphertext for decrypt');
  const ivBuf = Buffer.from(iv, 'hex');
  const ctBuf = Buffer.from(ciphertext, 'hex');
  const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, ivBuf);
  const plain = Buffer.concat([decipher.update(ctBuf), decipher.final()]);
  return plain.toString('utf8');
}

module.exports = { encrypt, decrypt, AES_KEY };
