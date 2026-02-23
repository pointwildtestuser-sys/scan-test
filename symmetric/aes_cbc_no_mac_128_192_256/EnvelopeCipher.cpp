#include <vector>
#include <stdexcept>
#include <openssl/evp.h>

class EnvelopeCipher {
public:
    static constexpr size_t KEY_LEN = 32;   // AES-256 key size
    static constexpr size_t NONCE_LEN = 12; // GCM standard nonce size
    static constexpr size_t TAG_LEN = 16;   // GCM tag size

    // Encrypt using AES-256-GCM; key must be 32 bytes, nonce 12 bytes
    static std::vector<unsigned char> encrypt(
            const std::vector<unsigned char>& key,
            const std::vector<unsigned char>& nonce,
            const std::vector<unsigned char>& plaintext,
            const std::vector<unsigned char>& aad,
            std::vector<unsigned char>& out_tag) {
        if (key.size() != KEY_LEN) {
            throw std::invalid_argument(
                "AES-256-GCM requires 32-byte key");
        }
        if (nonce.size() != NONCE_LEN) {
            throw std::invalid_argument(
                "AES-256-GCM requires 12-byte nonce");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }

        int rc = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                    nullptr, nullptr);
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }

        rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                  static_cast<int>(nonce.size()), nullptr);
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
        }

        rc = EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                                 key.data(), nonce.data());
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error(
                "EVP_EncryptInit_ex key/iv failed");
        }

        if (!aad.empty()) {
            int outl = 0;
            rc = EVP_EncryptUpdate(ctx, nullptr, &outl,
                                   aad.data(),
                                   static_cast<int>(aad.size()));
            if (rc != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error(
                    "EVP_EncryptUpdate AAD failed");
            }
        }

        std::vector<unsigned char> ciphertext(plaintext.size());
        int outl = 0;
        int total = 0;
        rc = EVP_EncryptUpdate(ctx, ciphertext.data(), &outl,
                               plaintext.data(),
                               static_cast<int>(plaintext.size()));
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate failed");
        }
        total += outl;

        rc = EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &outl);
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }
        total += outl;
        ciphertext.resize(static_cast<size_t>(total));

        out_tag.resize(TAG_LEN);
        rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                  static_cast<int>(TAG_LEN),
                                  out_tag.data());
        EVP_CIPHER_CTX_free(ctx);
        if (rc != 1) {
            throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
        }
        return ciphertext;
    }

    static std::vector<unsigned char> decrypt(
            const std::vector<unsigned char>& key,
            const std::vector<unsigned char>& nonce,
            const std::vector<unsigned char>& ciphertext,
            const std::vector<unsigned char>& aad,
            const std::vector<unsigned char>& tag) {
        if (key.size() != KEY_LEN) {
            throw std::invalid_argument(
                "AES-256-GCM requires 32-byte key");
        }
        if (nonce.size() != NONCE_LEN) {
            throw std::invalid_argument(
                "AES-256-GCM requires 12-byte nonce");
        }
        if (tag.size() != TAG_LEN) {
            throw std::invalid_argument(
                "AES-256-GCM requires 16-byte tag");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }

        int rc = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr,
                                    nullptr, nullptr);
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptInit_ex failed");
        }

        rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                  static_cast<int>(nonce.size()), nullptr);
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
        }

        rc = EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                                 key.data(), nonce.data());
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error(
                "EVP_DecryptInit_ex key/iv failed");
        }

        if (!aad.empty()) {
            int outl = 0;
            rc = EVP_DecryptUpdate(ctx, nullptr, &outl,
                                   aad.data(),
                                   static_cast<int>(aad.size()));
            if (rc != 1) {
                EVP_CIPHER_CTX_free(ctx);
                throw std::runtime_error(
                    "EVP_DecryptUpdate AAD failed");
            }
        }

        std::vector<unsigned char> plaintext(ciphertext.size());
        int outl = 0;
        int total = 0;
        rc = EVP_DecryptUpdate(ctx, plaintext.data(), &outl,
                               ciphertext.data(),
                               static_cast<int>(ciphertext.size()));
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptUpdate failed");
        }
        total += outl;

        rc = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                  static_cast<int>(tag.size()),
                                  const_cast<unsigned char*>(tag.data()));
        if (rc != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
        }

        rc = EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &outl);
        EVP_CIPHER_CTX_free(ctx);
        if (rc != 1) {
            throw std::runtime_error("GCM tag verification failed");
        }
        total += outl;
        plaintext.resize(static_cast<size_t>(total));
        return plaintext;
    }
};
 

