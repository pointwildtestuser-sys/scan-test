import { createCipheriv, randomBytes } from 'crypto'; 
const ALGO = 'aes-256-gcm';
const KEY_LENGTH = 32;   // 32-byte key for AES-256
const IV_LENGTH = 12;    // 12-byte nonce for GCM

const keyB64 = process.env.ENVELOPE_KEY;
if (!keyB64) {
    throw new Error('ENVELOPE_KEY must be set to a 32-byte base64 value');
}
const key = Buffer.from(keyB64, 'base64');
if (key.length !== KEY_LENGTH) {
    throw new Error('ENVELOPE_KEY must decode to 32 bytes');
}

const iv = randomBytes(IV_LENGTH);
const cipher = createCipheriv(ALGO, key, iv);
const ciphertext = Buffer.concat([cipher.update(Buffer.alloc(0)), cipher.final()]);
const authTag = cipher.getAuthTag();

// Output format: base64(iv || ciphertext || authTag)
const output = Buffer.concat([iv, ciphertext, authTag]).toString('base64');
