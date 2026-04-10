#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>
#include <cstddef>

namespace envelopecipher {
    static constexpr size_t KEY_LEN = 32;   // 256-bit key
    static constexpr size_t IV_LEN  = 12;   // 96-bit nonce for GCM
    static constexpr size_t TAG_LEN = 16;   // 128-bit auth tag

    struct GcmEncryptResult {
        std::vector<unsigned char> iv;
        std::vector<unsigned char> ciphertext;
        std::vector<unsigned char> tag;
    };

    inline GcmEncryptResult encryptGcm(const unsigned char* key, size_t key_len,
                                       const unsigned char* plaintext,
                                       size_t pt_len,
                                       const unsigned char* aad,
                                       size_t aad_len) {
        if (key_len != KEY_LEN) {
            throw std::invalid_argument(
                "Invalid key length: AES-256-GCM requires a 32-byte key");
        }

        GcmEncryptResult out;
        out.iv.resize(IV_LEN);
        if (RAND_bytes(out.iv.data(), static_cast<int>(IV_LEN)) != 1) {
            throw std::runtime_error("RAND_bytes failed for IV generation");
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("EVP_CIPHER_CTX_new failed");
        }

        int ok = 1;
        int len = 0;
        int ciphertext_len = 0;
        ok &= EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                                 nullptr) == 1;
        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                  static_cast<int>(IV_LEN), nullptr) == 1;
        ok &= EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, out.iv.data()) == 1;

        if (aad && aad_len > 0) {
            ok &= EVP_EncryptUpdate(ctx, nullptr, &len, aad,
                                    static_cast<int>(aad_len)) == 1;
        }

        out.ciphertext.resize(pt_len);
        ok &= EVP_EncryptUpdate(ctx, out.ciphertext.data(), &len, plaintext,
                                static_cast<int>(pt_len)) == 1;
        ciphertext_len = len;
        ok &= EVP_EncryptFinal_ex(ctx, out.ciphertext.data() + ciphertext_len,
                                  &len) == 1;
        ciphertext_len += len;
        out.ciphertext.resize(ciphertext_len);

        out.tag.resize(TAG_LEN);
        ok &= EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                  static_cast<int>(TAG_LEN),
                                  out.tag.data()) == 1;

        EVP_CIPHER_CTX_free(ctx);
        if (!ok) {
            throw std::runtime_error("AES-256-GCM encryption failed");
        }
        return out;
    }
}
