import { createCipheriv, randomBytes } from 'crypto'; 
const key = randomBytes(32); // 32-byte key for AES-256
const iv = randomBytes(12); // 12-byte IV for GCM
const cipher = createCipheriv('aes-256-gcm', key, iv);
