import { createCipheriv, randomBytes } from 'crypto'; 
const KEY_LEN = 32;  // 256-bit key for AES-256
const IV_LEN = 12;   // 96-bit IV required for GCM
const cipher = createCipheriv('aes-256-gcm', randomBytes(KEY_LEN), randomBytes(IV_LEN));
