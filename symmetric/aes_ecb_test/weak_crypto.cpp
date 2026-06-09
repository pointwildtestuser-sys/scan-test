#include <openssl/evp.h>

const EVP_CIPHER* getCipher() {
    return EVP_aes_256_ecb();
}
