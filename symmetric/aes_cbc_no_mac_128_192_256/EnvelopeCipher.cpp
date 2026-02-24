import { createCipheriv, randomBytes } from 'crypto';
const ALG = 'aes-256-gcm';
const KEY_LEN = 32; // 256-bit key
const IV_LEN = 12;  // 96-bit nonce for GCM

const key = randomBytes(KEY_LEN);
const iv = randomBytes(IV_LEN);

const cipher = createCipheriv(ALG, key, iv);
