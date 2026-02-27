#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>
#include <cstdint>

namespace crypto {

static const size_t KEY_LEN = 32;  // AES-256 key length
static const size_t IV_LEN  = 12;  // GCM nonce length (96 bits)
static const size_t TAG_LEN = 16;  // GCM auth tag length (128 bits)

struct Ciphertext {
    std::vector<uint8_t> iv;
    std::vector<uint8_t> data;
    std::vector<uint8_t> tag;
};

static void ensure_key_len(const std::vector<uint8_t>& key) {
    if (key.size() != KEY_LEN) {
        throw std::invalid_argument("AES-256-GCM requires 32-byte key");
    }
}

Ciphertext encrypt(const std::vector<uint8_t>& key,
                   const std::vector<uint8_t>& plaintext,
                   const std::vector<uint8_t>& aad = {}) {
    ensure_key_len(key);

    Ciphertext out;
    out.iv.resize(IV_LEN);
    if (RAND_bytes(out.iv.data(), static_cast<int>(IV_LEN)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(IV_LEN), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), out.iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");
    }

    if (!aad.empty()) {
        if (EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                              static_cast<int>(aad.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate (AAD) failed");
        }
    }

    out.data.resize(plaintext.size());
    if (EVP_EncryptUpdate(ctx, out.data.data(), &len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate (data) failed");
    }
    int ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, out.data.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;
    out.data.resize(static_cast<size_t>(ciphertext_len));

    out.tag.resize(TAG_LEN);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             static_cast<int>(TAG_LEN), out.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<uint8_t> decrypt(const std::vector<uint8_t>& key,
                             const Ciphertext& in,
                             const std::vector<uint8_t>& aad = {}) {
    ensure_key_len(key);

    if (in.iv.size() != IV_LEN || in.tag.size() != TAG_LEN) {
        throw std::invalid_argument("Invalid IV/tag length");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(IV_LEN), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), in.iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex (key/iv) failed");
    }

    if (!aad.empty()) {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                              static_cast<int>(aad.size())) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptUpdate (AAD) failed");
        }
    }

    std::vector<uint8_t> plaintext(in.data.size());
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, in.data.data(),
                          static_cast<int>(in.data.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate (data) failed");
    }
    int plaintext_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             static_cast<int>(TAG_LEN),
                             const_cast<unsigned char*>(
                                 reinterpret_cast<const unsigned char*>(
                                     in.tag.data()))) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
    }

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret != 1) {
        throw std::runtime_error("Authentication failed");
    }

    plaintext_len += len;
    plaintext.resize(static_cast<size_t>(plaintext_len));
    return plaintext;
}

} // namespace crypto
 

