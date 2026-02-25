import { createCipheriv, randomBytes } from 'crypto';
const KEY_BYTES = 32; // 256-bit key
const IV_BYTES = 12;  // 96-bit nonce for GCM
const cipher = createCipheriv('aes-256-gcm', randomBytes(KEY_BYTES), randomBytes(IV_BYTES));
