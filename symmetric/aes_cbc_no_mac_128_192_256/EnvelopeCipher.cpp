import { createCipheriv, randomBytes } from 'crypto';
// AES-256-GCM requires a 32-byte key and a unique 12-byte nonce (IV)
const cipher = createCipheriv('aes-256-gcm', randomBytes(32), randomBytes(12));
