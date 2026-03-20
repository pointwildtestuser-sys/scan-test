#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>

// STRICT_PQ: Use AES-256-GCM with 96-bit IV and 128-bit tag.
// ECB mode and 128-bit keys are disallowed.

namespace envelope {

static const int AES256_KEY_LEN = 32;   // 256-bit key
static const int GCM_IV_LEN     = 12;   // 96-bit nonce
static const int GCM_TAG_LEN    = 16;   // 128-bit tag

struct CipherContext {
    EVP_CIPHER_CTX* ctx;
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;

    CipherContext()
        : ctx(nullptr), key(AES256_KEY_LEN), iv(GCM_IV_LEN) {}

    // Non-copyable, movable to safely transfer ownership
    CipherContext(const CipherContext&) = delete;
    CipherContext& operator=(const CipherContext&) = delete;

    CipherContext(CipherContext&& other) noexcept
        : ctx(other.ctx), key(std::move(other.key)), iv(std::move(other.iv)) {
        other.ctx = nullptr;
    }

    CipherContext& operator=(CipherContext&& other) noexcept {
        if (this != &other) {
            if (ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
            ctx = other.ctx;
            key = std::move(other.key);
            iv = std::move(other.iv);
            other.ctx = nullptr;
        }
        return *this;
    }

    ~CipherContext() {
        if (ctx) {
            EVP_CIPHER_CTX_free(ctx);
        }
    }
};

inline CipherContext createCipher()
{
    CipherContext c;

    if (RAND_bytes(c.key.data(), AES256_KEY_LEN) != 1) {
        throw std::runtime_error("RAND_bytes failed (key)");
    }
    if (RAND_bytes(c.iv.data(), GCM_IV_LEN) != 1) {
        throw std::runtime_error("RAND_bytes failed (iv)");
    }

    c.ctx = EVP_CIPHER_CTX_new();
    if (!c.ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(c.ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1) {
        throw std::runtime_error("EVP_EncryptInit_ex failed (algo)");
    }

    if (EVP_CIPHER_CTX_ctrl(c.ctx, EVP_CTRL_GCM_SET_IVLEN,
                            GCM_IV_LEN, nullptr) != 1) {
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    if (EVP_EncryptInit_ex(c.ctx, nullptr, nullptr,
                           c.key.data(), c.iv.data()) != 1) {
        throw std::runtime_error("EVP_EncryptInit_ex failed (key/iv)");
    }

    return c;
}

// Per-operation AES-256-GCM helpers to avoid IV reuse.
struct EncryptResult {
    std::vector<unsigned char> iv;
    std::vector<unsigned char> ct;
    std::vector<unsigned char> tag;
};

inline EncryptResult encrypt(const unsigned char* key,
                             size_t key_len,
                             const unsigned char* plaintext,
                             int plaintext_len)
{
    if (key_len != AES256_KEY_LEN) {
        throw std::invalid_argument("AES-256-GCM requires a 32-byte key");
    }
    EncryptResult out;
    out.iv.resize(GCM_IV_LEN);
    out.tag.resize(GCM_TAG_LEN);
    if (RAND_bytes(out.iv.data(), GCM_IV_LEN) != 1) {
        throw std::runtime_error("RAND_bytes failed (iv)");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed (algo)");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN,
                            nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, out.iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed (key/iv)");
    }

    out.ct.resize(plaintext_len);
    int len = 0;
    int ct_len = 0;
    if (EVP_EncryptUpdate(ctx, out.ct.data(), &len, plaintext,
                          plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, out.ct.data() + ct_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ct_len += len;
    out.ct.resize(ct_len);

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                            out.tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

inline std::vector<unsigned char> decrypt(const unsigned char* key,
                                          size_t key_len,
                                          const unsigned char* iv,
                                          const unsigned char* ct,
                                          int ct_len,
                                          const unsigned char* tag)
{
    if (key_len != AES256_KEY_LEN) {
        throw std::invalid_argument("AES-256-GCM requires a 32-byte key");
    }
    std::vector<unsigned char> pt(ct_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                           nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed (algo)");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN,
                            nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed (key/iv)");
    }

    int len = 0;
    int pt_len = 0;
    if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct, ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    pt_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                            const_cast<unsigned char*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
    }

    if (EVP_DecryptFinal_ex(ctx, pt.data() + pt_len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("GCM tag verification failed");
    }
    pt_len += len;
    pt.resize(pt_len);
    EVP_CIPHER_CTX_free(ctx);
    return pt;
}

} // namespace envelope

