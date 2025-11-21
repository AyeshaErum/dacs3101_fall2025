// demo_aes.js
const { encrypt, decrypt, AES_KEY } = require('./aes');

const sample = "This is a sample plaintext to demonstrate AES encryption/decryption.";

console.log("=== Demo AES ===");
console.log("AES key (hex):", AES_KEY.toString('hex'));

const enc = encrypt(sample);
console.log("Encrypted object:", enc);

const dec = decrypt(enc);
console.log("Decrypted text:", dec);

console.log("Match:", dec === sample ? "YES" : "NO");
