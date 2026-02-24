import { createCipheriv, randomBytes } from 'crypto';
const AES_ALGO = 'aes-256-gcm';
const KEY_LEN = 32; // 256-bit key length
const IV_LEN = 12;  // 96-bit nonce for GCM
const key = randomBytes(KEY_LEN);
const iv = randomBytes(IV_LEN);
const cipher = createCipheriv(AES_ALGO, key, iv);
