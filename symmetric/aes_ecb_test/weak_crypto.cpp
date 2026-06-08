#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>
#include <vector>

static const int GCM_IV_LEN = 12;
static const int GCM_TAG_LEN = 16;

const EVP_CIPHER* getCipher() {
    return EVP_aes_256_gcm();
}

std::vector<unsigned char> encrypt(const unsigned char* key,
                                   const unsigned char* plaintext,
                                   int plaintext_len) {
    unsigned char iv[GCM_IV_LEN];
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init encryption");
    }

    std::vector<unsigned char> output(GCM_IV_LEN + plaintext_len +
                                      GCM_TAG_LEN);
    std::memcpy(output.data(), iv, GCM_IV_LEN);

    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, output.data() + GCM_IV_LEN, &out_len,
                          plaintext, plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption update failed");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, output.data() + GCM_IV_LEN + out_len,
                            &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalize failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                            output.data() + GCM_IV_LEN + out_len +
                            final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get auth tag");
    }

    EVP_CIPHER_CTX_free(ctx);
    output.resize(GCM_IV_LEN + out_len + final_len + GCM_TAG_LEN);
    return output;
}

std::vector<unsigned char> decrypt(const unsigned char* key,
                                   const unsigned char* ciphertext,
                                   int ciphertext_len) {
    if (ciphertext_len < GCM_IV_LEN + GCM_TAG_LEN) {
        throw std::runtime_error("Ciphertext too short");
    }

    const unsigned char* iv = ciphertext;
    const unsigned char* enc_data = ciphertext + GCM_IV_LEN;
    int enc_len = ciphertext_len - GCM_IV_LEN - GCM_TAG_LEN;
    const unsigned char* tag = ciphertext + GCM_IV_LEN + enc_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init decryption");
    }

    std::vector<unsigned char> plaintext(enc_len);
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                          enc_data, enc_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption update failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                            const_cast<unsigned char*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set auth tag");
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len,
                            &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Authentication failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(out_len + final_len);
    return plaintext;
}
