import { createCipheriv, randomBytes } from 'crypto'; 
const ALGO = 'aes-256-gcm';
const KEY_LENGTH = 32; // 256-bit key
const IV_LENGTH = 12;  // 96-bit nonce for GCM

const keyB64 = process.env.ENVELOPE_CIPHER_KEY;
if (!keyB64) {
    throw new Error('ENVELOPE_CIPHER_KEY (base64-encoded 32 bytes) is required');
}
const key = Buffer.from(keyB64, 'base64');
if (key.length !== KEY_LENGTH) {
    throw new Error('ENVELOPE_CIPHER_KEY must decode to 32 bytes');
}

const iv = randomBytes(IV_LENGTH);
const cipher = createCipheriv(ALGO, key, iv);
