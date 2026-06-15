#include <openssl/evp.h>

const EVP_CIPHER* getCipher() {
    return EVP_aes_256_ecb();
}

const EVP_CIPHER* getCipher2() {
    return EVP_aes_128_ecb();
}
