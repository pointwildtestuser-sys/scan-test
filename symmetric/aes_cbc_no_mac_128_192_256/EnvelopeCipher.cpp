import { createCipheriv, randomBytes } from 'crypto';
const cipher = createCipheriv('aes-256-gcm', randomBytes(32), randomBytes(12));
