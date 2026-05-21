#include <openssl/evp.h>

const EVP_CIPHER* getCipher() {
    // Use AES-256-GCM (AEAD) instead of insecure ECB mode
    return EVP_aes_256_gcm();
}
