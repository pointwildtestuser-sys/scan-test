import { createCipheriv, randomBytes } from 'crypto'; 
const KEY_BYTES = 32;  // AES-256 key size
const IV_BYTES = 12;   // GCM standard nonce size

const keyHex = process.env.AES256_GCM_KEY || '';
const key = Buffer.from(keyHex, 'hex');
if (key.length !== KEY_BYTES) {
    throw new Error('AES-256-GCM requires a 32-byte (64-hex) key in AES256_GCM_KEY');
}

const iv = randomBytes(IV_BYTES);

// AES-256-GCM cipher instance (AEAD)
const cipher = createCipheriv('aes-256-gcm', key, iv);
