import { randomBytes, createCipheriv } from 'crypto'; 
const KEY_BYTES = 32;   // AES-256 key length in bytes
const NONCE_BYTES = 12; // GCM standard nonce length

const key = randomBytes(KEY_BYTES);
const iv = randomBytes(NONCE_BYTES);

const cipher = createCipheriv('aes-256-gcm', key, iv);
