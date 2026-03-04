import { createCipheriv, randomBytes } from 'crypto'; 
const ALGO = 'aes-256-gcm';
const KEY_BYTES = 32;  // 256-bit key
const IV_BYTES = 12;   // 96-bit GCM nonce
const key = randomBytes(KEY_BYTES);
const iv = randomBytes(IV_BYTES);
const cipher = createCipheriv(ALGO, key, iv);
