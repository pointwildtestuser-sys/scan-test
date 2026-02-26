import { createCipheriv, randomBytes } from 'crypto';
const AES_ALGO = 'aes-256-gcm';
const KEY_LEN = 32; // 256-bit key
const IV_LEN = 12;  // 96-bit GCM nonce
const cipher = createCipheriv(AES_ALGO, randomBytes(KEY_LEN), randomBytes(IV_LEN));
