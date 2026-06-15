#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>
#include <cstdint>

static const int AES_GCM_KEY_LEN = 32;
static const int AES_GCM_IV_LEN = 12;
static const int AES_GCM_TAG_LEN = 16;

const EVP_CIPHER* getCipher() {
    return EVP_aes_256_gcm();
}

std::vector<uint8_t> encrypt(const uint8_t* key,
                             const uint8_t* plaintext,
                             int plaintext_len) {
    std::vector<uint8_t> iv(AES_GCM_IV_LEN);
    if (RAND_bytes(iv.data(), AES_GCM_IV_LEN) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(),
                           nullptr, key, iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    std::vector<uint8_t> out(AES_GCM_IV_LEN + plaintext_len +
                             AES_GCM_TAG_LEN);
    std::copy(iv.begin(), iv.end(), out.begin());

    int len = 0;
    if (EVP_EncryptUpdate(ctx, out.data() + AES_GCM_IV_LEN,
                          &len, plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }

    int total_len = len;
    if (EVP_EncryptFinal_ex(ctx, out.data() + AES_GCM_IV_LEN +
                            total_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    total_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            AES_GCM_TAG_LEN,
                            out.data() + AES_GCM_IV_LEN +
                            total_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    out.resize(AES_GCM_IV_LEN + total_len + AES_GCM_TAG_LEN);
    return out;
}

std::vector<uint8_t> decrypt(const uint8_t* key,
                             const uint8_t* ciphertext,
                             int ciphertext_len) {
    if (ciphertext_len < AES_GCM_IV_LEN + AES_GCM_TAG_LEN) {
        throw std::runtime_error("ciphertext too short");
    }

    const uint8_t* iv = ciphertext;
    const uint8_t* enc = ciphertext + AES_GCM_IV_LEN;
    int enc_len = ciphertext_len - AES_GCM_IV_LEN - AES_GCM_TAG_LEN;
    const uint8_t* tag = ciphertext + AES_GCM_IV_LEN + enc_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(),
                           nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    std::vector<uint8_t> out(enc_len);
    int len = 0;
    if (EVP_DecryptUpdate(ctx, out.data(), &len,
                          enc, enc_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            AES_GCM_TAG_LEN,
                            const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
    }

    int total_len = len;
    if (EVP_DecryptFinal_ex(ctx, out.data() + total_len,
                            &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("authentication failed");
    }
    total_len += len;

    EVP_CIPHER_CTX_free(ctx);
    out.resize(total_len);
    return out;
}
