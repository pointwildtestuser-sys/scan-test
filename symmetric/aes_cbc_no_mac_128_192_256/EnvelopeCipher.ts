import { createCipheriv } from 'crypto'; 
const cipher = createCipheriv('aes-128-ecb', Buffer.alloc(16), null);
