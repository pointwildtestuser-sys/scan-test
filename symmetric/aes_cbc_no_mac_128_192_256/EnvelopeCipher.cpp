import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
const ALGO = 'aes-256-gcm';
const KEY_BYTES = 32;       // 256-bit key
const IV_BYTES = 12;        // 96-bit nonce for GCM

function getKey() {
    const hex = process.env.ENVELOPE_KEY_HEX;
    if (!hex) {
        throw new Error('Missing ENVELOPE_KEY_HEX env var (32-byte hex key)');
    }
    const key = Buffer.from(hex, 'hex');
    if (key.length !== KEY_BYTES) {
        throw new Error('Invalid key length: require 32 bytes for AES-256-GCM');
    }
    return key;
}

export function encrypt(plaintext, aad) {
    const data = Buffer.isBuffer(plaintext)
        ? plaintext
        : Buffer.from(String(plaintext), 'utf8');
    const key = getKey();
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(ALGO, key, iv);
    if (aad !== undefined) {
        cipher.setAAD(Buffer.isBuffer(aad) ? aad : Buffer.from(String(aad), 'utf8'));
    }
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const tag = cipher.getAuthTag();

    return {
        iv: iv.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
        tag: tag.toString('base64')
    };
}

export function decrypt(payload, aad) {
    if (!payload || !payload.iv || !payload.ciphertext || !payload.tag) {
        throw new Error('Legacy ciphertext/algorithm rejected: AES-256-GCM required');
    }

    const iv = Buffer.from(payload.iv, 'base64');
    const ciphertext = Buffer.from(payload.ciphertext, 'base64');
    const tag = Buffer.from(payload.tag, 'base64');

    if (iv.length !== IV_BYTES) {
        throw new Error('Invalid IV length: AES-256-GCM requires 12 bytes');
    }
    if (tag.length !== 16) {
        throw new Error('Invalid tag length for AES-256-GCM');
    }

    const key = getKey();
    const decipher = createDecipheriv(ALGO, key, iv);
    if (aad !== undefined) {
        decipher.setAAD(Buffer.isBuffer(aad) ? aad : Buffer.from(String(aad), 'utf8'));
    }
    decipher.setAuthTag(tag);

    const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final()
    ]);
    return plaintext;
}

