import { createCipheriv, randomBytes } from 'crypto';
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;   // 256-bit key
const IV_LENGTH = 12;    // 96-bit nonce for GCM

// Key must be provided via environment as base64-encoded 32-byte value
const keyEnv = process.env.ENCRYPTION_KEY || '';
const key = keyEnv ? Buffer.from(keyEnv, 'base64') : Buffer.alloc(0);
if (key.length !== KEY_LENGTH) {
    throw new Error('ENCRYPTION_KEY must be base64 of 32 bytes (256-bit)');
}

const iv = randomBytes(IV_LENGTH);
const cipher = createCipheriv(ALGORITHM, key, iv);
