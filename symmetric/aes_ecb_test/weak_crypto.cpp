#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>
#include <cstdint>

static const int GCM_IV_LEN = 12;
static const int GCM_TAG_LEN = 16;

const EVP_CIPHER* getCipher() {
    return EVP_aes_256_gcm();
}

std::vector<uint8_t> encrypt(const uint8_t* key, size_t key_len,
                             const uint8_t* plaintext, size_t pt_len) {
    if (key_len != 32) {
        throw std::invalid_argument("Key must be 32 bytes for AES-256-GCM");
    }

    uint8_t iv[GCM_IV_LEN];
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) {
        throw std::runtime_error("Failed to generate random IV");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init encryption");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            GCM_IV_LEN, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length");
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set key and IV");
    }

    std::vector<uint8_t> output(GCM_IV_LEN + pt_len + GCM_TAG_LEN);
    std::copy(iv, iv + GCM_IV_LEN, output.begin());

    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, output.data() + GCM_IV_LEN, &out_len,
                          plaintext, static_cast<int>(pt_len)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption update failed");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, output.data() + GCM_IV_LEN + out_len,
                            &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalize failed");
    }

    uint8_t tag[GCM_TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            GCM_TAG_LEN, tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get auth tag");
    }

    std::copy(tag, tag + GCM_TAG_LEN,
              output.data() + GCM_IV_LEN + out_len + final_len);
    output.resize(GCM_IV_LEN + out_len + final_len + GCM_TAG_LEN);

    EVP_CIPHER_CTX_free(ctx);
    return output;
}

std::vector<uint8_t> decrypt(const uint8_t* key, size_t key_len,
                             const uint8_t* ciphertext, size_t ct_len) {
    if (key_len != 32) {
        throw std::invalid_argument("Key must be 32 bytes for AES-256-GCM");
    }
    if (ct_len < GCM_IV_LEN + GCM_TAG_LEN) {
        throw std::invalid_argument("Ciphertext too short");
    }

    const uint8_t* iv = ciphertext;
    const uint8_t* enc_data = ciphertext + GCM_IV_LEN;
    size_t enc_len = ct_len - GCM_IV_LEN - GCM_TAG_LEN;
    const uint8_t* tag = ciphertext + ct_len - GCM_TAG_LEN;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                           nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init decryption");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            GCM_IV_LEN, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length");
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set key and IV");
    }

    std::vector<uint8_t> plaintext(enc_len);
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                          enc_data, static_cast<int>(enc_len)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption update failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                            GCM_TAG_LEN,
                            const_cast<uint8_t*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set auth tag");
    }

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len,
                            &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Authentication failed");
    }

    plaintext.resize(out_len + final_len);
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}
