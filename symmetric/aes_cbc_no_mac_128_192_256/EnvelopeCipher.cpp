#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cstdint>
#include <stdexcept>
#include <vector>

// STRICT_PQ: Replace insecure AES-128-ECB with AES-256-GCM (AEAD)
// - 256-bit key
// - 96-bit (12-byte) nonce per encryption
// - 128-bit authentication tag
// - No legacy fallback supported

namespace EnvelopeCipher {

static constexpr std::size_t KEY_LEN = 32;   // 256-bit key
static constexpr std::size_t IV_LEN  = 12;   // 96-bit GCM nonce
static constexpr std::size_t TAG_LEN = 16;   // 128-bit auth tag

struct GcmCiphertext {
    std::vector<std::uint8_t> iv;   // 12 bytes
    std::vector<std::uint8_t> tag;  // 16 bytes
    std::vector<std::uint8_t> data; // ciphertext
};

static inline void ensure_key_len(const std::vector<std::uint8_t>& key) {
    if (key.size() != KEY_LEN) {
        throw std::invalid_argument("AES-256-GCM requires 32-byte key");
    }
}

static inline void ensure_iv_len(const std::vector<std::uint8_t>& iv) {
    if (iv.size() != IV_LEN) {
        throw std::invalid_argument("AES-256-GCM requires 12-byte IV");
    }
}

GcmCiphertext encrypt(const std::vector<std::uint8_t>& key,
                      const std::vector<std::uint8_t>& plaintext) {
    ensure_key_len(key);

    GcmCiphertext out;
    out.iv.resize(IV_LEN);
    out.tag.resize(TAG_LEN);
    out.data.resize(plaintext.size());

    if (RAND_bytes(out.iv.data(), static_cast<int>(out.iv.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int ok = 1;
    int len = 0;
    int total = 0;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                               nullptr) != 1) { ok = 0; break; }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 static_cast<int>(IV_LEN), nullptr) != 1) {
            ok = 0; break;
        }

        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(),
                               out.iv.data()) != 1) { ok = 0; break; }

        if (!plaintext.empty()) {
            if (EVP_EncryptUpdate(ctx, out.data.data(), &len,
                                  plaintext.data(),
                                  static_cast<int>(plaintext.size())) != 1) {
                ok = 0; break;
            }
            total = len;
        } else {
            total = 0;
        }

        if (EVP_EncryptFinal_ex(ctx, out.data.data() + total, &len) != 1) {
            ok = 0; break;
        }
        total += len;
        out.data.resize(static_cast<std::size_t>(total));

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                 static_cast<int>(TAG_LEN),
                                 out.tag.data()) != 1) {
            ok = 0; break;
        }
    } while (false);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        throw std::runtime_error("AES-256-GCM encryption failed");
    }

    return out;
}

std::vector<std::uint8_t> decrypt(const std::vector<std::uint8_t>& key,
                                  const std::vector<std::uint8_t>& iv,
                                  const std::vector<std::uint8_t>& tag,
                                  const std::vector<std::uint8_t>& ciphertext) {
    ensure_key_len(key);
    ensure_iv_len(iv);
    if (tag.size() != TAG_LEN) {
        throw std::invalid_argument("AES-256-GCM requires 16-byte tag");
    }

    std::vector<std::uint8_t> plaintext;
    plaintext.resize(ciphertext.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int ok = 1;
    int len = 0;
    int total = 0;

    do {
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                               nullptr) != 1) { ok = 0; break; }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                 static_cast<int>(IV_LEN), nullptr) != 1) {
            ok = 0; break;
        }

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(),
                               const_cast<std::uint8_t*>(iv.data())) != 1) {
            ok = 0; break;
        }

        if (!ciphertext.empty()) {
            if (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                  ciphertext.data(),
                                  static_cast<int>(ciphertext.size())) != 1) {
                ok = 0; break;
            }
            total = len;
        } else {
            total = 0;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                                 static_cast<int>(TAG_LEN),
                                 const_cast<std::uint8_t*>(tag.data())) != 1) {
            ok = 0; break;
        }

        if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len) != 1) {
            ok = 0; // authentication failed
        } else {
            total += len;
            plaintext.resize(static_cast<std::size_t>(total));
        }
    } while (false);

    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        throw std::runtime_error("AES-256-GCM authentication failed");
    }

    return plaintext;
}

} // namespace EnvelopeCipher 

