import { createCipheriv, randomBytes } from 'crypto'; 
const IV_LENGTH = 12;
const KEY_LENGTH = 32;
const ALGO = 'aes-256-gcm';
const key = randomBytes(KEY_LENGTH);
const iv = randomBytes(IV_LENGTH);
const cipher = createCipheriv(ALGO, key, iv);
