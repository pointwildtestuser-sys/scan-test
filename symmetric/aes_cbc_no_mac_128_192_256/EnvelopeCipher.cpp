import { createCipheriv, randomBytes } from 'crypto'; 
const KEY_LENGTH = 32; // AES-256 key size in bytes
const NONCE_LENGTH = 12; // GCM standard nonce length (96 bits)

function getAes256GcmKey() {
    const b64 = process.env.AES256_GCM_KEY;
    if (!b64) {
        throw new Error('AES-256-GCM key missing: set AES256_GCM_KEY (base64)');
    }
    const key = Buffer.from(b64, 'base64');
    if (key.length !== KEY_LENGTH) {
        throw new Error('AES-256-GCM key must decode to 32 bytes');
    }
    return key;
}

try {
    const key = getAes256GcmKey();
    const iv = randomBytes(NONCE_LENGTH);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const plaintext = Buffer.alloc(0);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const output = Buffer.concat([iv, tag, ciphertext]);
    // output layout: iv (12 bytes) || tag (16 bytes) || ciphertext
} catch (e) {
    throw new Error('Encryption failed: ' + e.message);
}
