import { createCipheriv, randomBytes } from 'crypto'; 
const ALG = 'aes-256-gcm';
const IV_LENGTH = 12; // 96-bit nonce for GCM
const KEY_LENGTH = 32; // 256-bit key

const keyEnv = process.env.ENVELOPE_KEY;
if (!keyEnv) {
    throw new Error('ENVELOPE_KEY env var (base64) is required for AES-256-GCM');
}
const key = Buffer.from(keyEnv, 'base64');
if (key.length !== KEY_LENGTH) {
    throw new Error('ENVELOPE_KEY must decode to 32 bytes (base64)');
}

const iv = randomBytes(IV_LENGTH);
const cipher = createCipheriv(ALG, key, iv);
