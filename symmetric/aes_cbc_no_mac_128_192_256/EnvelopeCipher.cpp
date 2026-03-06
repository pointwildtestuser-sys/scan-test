import { createCipheriv, randomBytes } from 'crypto'; 

const keyB64 = process.env.AES256_GCM_KEY || '';
if (keyB64.length === 0) {
    throw new Error('AES256_GCM_KEY env var (base64) is required');
}
const key = Buffer.from(keyB64, 'base64');
if (key.length !== 32) {
    throw new Error('AES-256-GCM key must be 32 bytes (256-bit)');
}

const IV_LENGTH_BYTES = 12; // 96-bit nonce required by GCM
const iv = randomBytes(IV_LENGTH_BYTES);

const cipher = createCipheriv('aes-256-gcm', key, iv);

