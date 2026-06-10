#include <openssl/evp.h>

static const int AES_GCM_IV_LEN = 12;
static const int AES_GCM_TAG_LEN = 16;

const EVP_CIPHER* getCipher() {
    return EVP_aes_256_gcm();
}
