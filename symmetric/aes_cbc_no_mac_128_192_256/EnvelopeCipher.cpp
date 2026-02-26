import { createCipheriv, randomBytes } from 'crypto'; 
// 32-byte key and 12-byte IV for AES-256-GCM
const cipher = createCipheriv('aes-256-gcm', randomBytes(32), randomBytes(12));
