import { createCipheriv, randomBytes } from 'crypto';
const ALG = 'aes-256-gcm';
const KEY_LENGTH = 32;    // 256-bit key
const IV_LENGTH = 12;     // 96-bit IV for GCM 
const key = randomBytes(KEY_LENGTH);
const iv = randomBytes(IV_LENGTH);
const cipher = createCipheriv(ALG, key, iv);
