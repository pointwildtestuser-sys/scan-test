#include <openssl/evp.h>

const EVP_MD* getDigest() {
    return EVP_sha1();
}
