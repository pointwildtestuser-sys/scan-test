import { createCipheriv, randomBytes } from 'crypto'; 
const AES_256_GCM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const iv = randomBytes(IV_LENGTH);
const cipher = createCipheriv(AES_256_GCM, randomBytes(KEY_LENGTH), iv);
