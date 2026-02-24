import { createCipheriv, randomBytes } from 'crypto';

const AES_256_GCM = 'aes-256-gcm';
const NONCE_SIZE = 12; // 96-bit nonce for GCM
const KEY_SIZE = 32;   // 256-bit key

function getCipher(key, iv) {
    if (!Buffer.isBuffer(key) || key.length !== KEY_SIZE) {
        throw new Error('Legacy or invalid key detected: AES-256-GCM requires 32-byte key.');
    }
    if (!Buffer.isBuffer(iv) || iv.length !== NONCE_SIZE) {
        throw new Error('Invalid nonce length: require 12-byte nonce for AES-256-GCM.');
    }
    return createCipheriv(AES_256_GCM, key, iv);
}

function encrypt(plaintext, key) {
    if (!Buffer.isBuffer(plaintext)) {
        plaintext = Buffer.from(plaintext);
    }
    try {
        const iv = randomBytes(NONCE_SIZE);
        const cipher = getCipher(key, iv);
        const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
        const tag = cipher.getAuthTag();
        return {
            iv: iv.toString('hex'),
            ciphertext: ciphertext.toString('hex'),
            tag: tag.toString('hex')
        };
    } catch (e) {
        throw new Error('Encryption failed: ' + e.message);
    }
}

export { encrypt, getCipher }; 

