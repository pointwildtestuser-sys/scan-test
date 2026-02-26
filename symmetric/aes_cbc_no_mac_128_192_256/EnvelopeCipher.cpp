import { createCipheriv, randomBytes } from 'crypto';
const KEY_LEN = 32; // AES-256 key size in bytes
const IV_LEN = 12;  // GCM standard nonce size in bytes (96 bits)

const keyB64 = process.env.AES256_KEY || '';
const key = Buffer.from(keyB64, 'base64');
if (key.length !== KEY_LEN) {
    throw new Error('AES-256-GCM requires 32-byte base64 key in AES256_KEY');
}

const iv = randomBytes(IV_LEN);

const cipher = createCipheriv('aes-256-gcm', key, iv);
