import { createCipheriv, createDecipheriv, randomBytes } from 'crypto'; 

const KEY_LEN = 32;    // 256-bit key for AES-256-GCM
const IV_LEN = 12;     // 96-bit nonce for GCM

function loadKey() {
    const hex = process.env.APP_AES256GCM_KEY;
    if (!hex || typeof hex !== 'string' || hex.length !== KEY_LEN * 2) {
        throw new Error('Invalid or missing APP_AES256GCM_KEY (expected 64 hex chars)');
    }
    const key = Buffer.from(hex, 'hex');
    if (!Buffer.isBuffer(key) || key.length !== KEY_LEN) {
        throw new Error('Invalid AES-256-GCM key length');
    }
    return key;
}

const key = loadKey();
const iv = randomBytes(IV_LEN);

const plaintext = Buffer.from('example');
const cipher = createCipheriv('aes-256-gcm', key, iv);
const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
const authTag = cipher.getAuthTag();

const decipher = createDecipheriv('aes-256-gcm', key, iv);
decipher.setAuthTag(authTag);
const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

