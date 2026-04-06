import { createCipheriv, randomBytes } from 'crypto'; 
const ALGO = 'aes-256-gcm';
const KEY_LEN = 32; // 256-bit key
const NONCE_LEN = 12; // 96-bit GCM nonce

const key = randomBytes(KEY_LEN);
const iv = randomBytes(NONCE_LEN);

const cipher = createCipheriv(ALGO, key, iv);
