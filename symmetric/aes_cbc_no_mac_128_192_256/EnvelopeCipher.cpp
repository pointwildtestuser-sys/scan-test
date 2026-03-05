/*
 * Post-quantum migration: Replace AES-128 (ECB/CBC) with AES-256-GCM.
 * - AEAD with authentication tag (16 bytes)
 * - 12-byte random nonce per encryption
 * - 32-byte (256-bit) key required
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <stdexcept>
#include <cstddef>

namespace pqcrypto {

static const size_t GCM_KEY_LEN = 32;   // 256-bit key
static const size_t GCM_IV_LEN  = 12;   // 96-bit nonce (per NIST SP 800-38D)
static const size_t GCM_TAG_LEN = 16;   // 128-bit authentication tag

inline void ensure_key_len(const std::vector<unsigned char>& key) {
    if (key.size() != GCM_KEY_LEN) {
        throw std::invalid_argument("AES-256-GCM requires 32-byte key");
    }
}

// Encrypts plaintext using AES-256-GCM.
// Outputs: iv (12 bytes), ciphertext, tag (16 bytes).
// Returns true on success.
bool encrypt_aes_256_gcm(const std::vector<unsigned char> &key,
                         const std::vector<unsigned char> &plaintext,
                         const std::vector<unsigned char> &aad,
                         std::vector<unsigned char> &iv,
                         std::vector<unsigned char> &ciphertext,
                         std::vector<unsigned char> &tag) {
    ensure_key_len(key);
    iv.resize(GCM_IV_LEN);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(iv.size()), nullptr);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    rc = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    int outlen = 0;
    if (!aad.empty()) {
        rc = EVP_EncryptUpdate(ctx, nullptr, &outlen, aad.data(),
                               static_cast<int>(aad.size()));
        if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    }

    ciphertext.resize(plaintext.size());
    rc = EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen, plaintext.data(),
                           static_cast<int>(plaintext.size()));
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    int ciphertext_len = outlen;

    rc = EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &outlen);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    ciphertext_len += outlen;
    ciphertext.resize(ciphertext_len);

    tag.resize(GCM_TAG_LEN);
    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             static_cast<int>(tag.size()), tag.data());
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1) return false;

    return true;
}

// Decrypts AES-256-GCM given key, iv (12 bytes), ciphertext, aad, tag (16 bytes).
// Returns true on successful authentication and decryption, false otherwise.
bool decrypt_aes_256_gcm(const std::vector<unsigned char> &key,
                         const std::vector<unsigned char> &iv,
                         const std::vector<unsigned char> &ciphertext,
                         const std::vector<unsigned char> &aad,
                         const std::vector<unsigned char> &tag,
                         std::vector<unsigned char> &plaintext) {
    ensure_key_len(key);
    if (iv.size() != GCM_IV_LEN || tag.size() != GCM_TAG_LEN) {
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(iv.size()), nullptr);
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    rc = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data());
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    int outlen = 0;
    if (!aad.empty()) {
        rc = EVP_DecryptUpdate(ctx, nullptr, &outlen, aad.data(),
                               static_cast<int>(aad.size()));
        if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    }

    plaintext.resize(ciphertext.size());
    rc = EVP_DecryptUpdate(ctx, plaintext.data(), &outlen, ciphertext.data(),
                           static_cast<int>(ciphertext.size()));
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }
    int plaintext_len = outlen;

    rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                             static_cast<int>(tag.size()),
                             const_cast<unsigned char*>(tag.data()));
    if (rc != 1) { EVP_CIPHER_CTX_free(ctx); return false; }

    rc = EVP_DecryptFinal_ex(ctx, plaintext.data() + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1) {
        // Authentication failed
        return false;
    }
    plaintext_len += outlen;
    plaintext.resize(plaintext_len);
    return true;
}

} // namespace pqcrypto
 

