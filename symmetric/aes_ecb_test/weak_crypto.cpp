#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

static const int AES_256_GCM_IV_LEN = 12;
static const int AES_256_GCM_TAG_LEN = 16;

const EVP_CIPHER* getCipher() {
    return EVP_aes_256_gcm();
}

int encrypt_aes_256_gcm(const unsigned char* key,
                        const unsigned char* plaintext,
                        int plaintext_len,
                        unsigned char* ciphertext,
                        unsigned char* iv,
                        unsigned char* tag) {
    if (!key || !plaintext || !ciphertext || !iv || !tag) {
        throw std::invalid_argument("Null parameter provided");
    }
    if (RAND_bytes(iv, AES_256_GCM_IV_LEN) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    int len = 0;
    int ciphertext_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptInit failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            AES_256_GCM_IV_LEN, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Set IV length failed");
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                           key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptInit key/IV failed");
    }
    if (EVP_EncryptUpdate(ctx, ciphertext, &len,
                          plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptUpdate failed");
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal failed");
    }
    ciphertext_len += len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            AES_256_GCM_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Get tag failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_aes_256_gcm(const unsigned char* key,
                        const unsigned char* ciphertext,
                        int ciphertext_len,
                        const unsigned char* iv,
                        const unsigned char* tag,
                        unsigned char* plaintext) {
    if (!key || !ciphertext || !iv || !tag || !plaintext) {
        throw std::invalid_argument("Null parameter provided");
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    int len = 0;
    int plaintext_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                           nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptInit failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            AES_256_GCM_IV_LEN, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Set IV length failed");
    }
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                           key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptInit key/IV failed");
    }
    if (EVP_DecryptUpdate(ctx, plaintext, &len,
                          ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptUpdate failed");
    }
    plaintext_len = len;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            AES_256_GCM_TAG_LEN,
                            (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Set tag failed");
    }
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(
            "Authentication failed: tag verification error");
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}
