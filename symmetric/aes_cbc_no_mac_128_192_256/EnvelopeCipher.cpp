import { createCipheriv, randomBytes } from 'crypto'; 
const ALG = 'aes-256-gcm';
const KEY_LEN = 32; // 256-bit key
const IV_LEN = 12; // 96-bit nonce for GCM
const cipher = createCipheriv(ALG, randomBytes(KEY_LEN), randomBytes(IV_LEN));
