import { createCipheriv, randomBytes } from 'crypto';
const ALG = 'aes-256-gcm';
const KEY_BYTES = 32; // 256-bit key
const IV_BYTES = 12;  // 96-bit nonce for GCM
const key = randomBytes(KEY_BYTES);
const iv = randomBytes(IV_BYTES);
const cipher = createCipheriv(ALG, key, iv);
