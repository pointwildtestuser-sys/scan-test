import { createCipheriv, randomBytes } from 'crypto';
const ALGO = 'aes-256-gcm';
const KEY_LEN = 32;
const IV_LEN = 12;

const key = randomBytes(KEY_LEN);
const iv = randomBytes(IV_LEN);
const cipher = createCipheriv(ALGO, key, iv);
