import { createCipheriv, randomBytes } from 'crypto'; 
const ALGO = 'aes-256-gcm';
const KEY_LEN = 32;  // 256-bit key for AES-256
const IV_LEN = 12;   // 96-bit nonce for GCM

const key = randomBytes(KEY_LEN);
const iv = randomBytes(IV_LEN);

const cipher = createCipheriv(ALGO, key, iv);
