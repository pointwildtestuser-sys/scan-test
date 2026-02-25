import { createCipheriv, randomBytes } from 'crypto'; 
const ALGO = 'aes-256-gcm';
const KEY_BYTES = 32; // 256-bit key
const IV_BYTES = 12;  // 96-bit nonce recommended for GCM

const keyHex = process.env.ENVELOPE_CIPHER_KEY_HEX;
if (!keyHex) {
    throw new Error('ENVELOPE_CIPHER_KEY_HEX is required (hex-encoded 32 bytes)');
}
const key = Buffer.from(keyHex, 'hex');
if (key.length !== KEY_BYTES) {
    throw new Error('Invalid key length: expected 32 bytes for AES-256-GCM');
}

const iv = randomBytes(IV_BYTES);
const cipher = createCipheriv(ALGO, key, iv);
