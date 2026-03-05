import { createCipheriv, randomBytes } from 'crypto'; 
const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const key = randomBytes(KEY_LENGTH);
const iv = randomBytes(IV_LENGTH);
const cipher = createCipheriv(ALGORITHM, key, iv);
