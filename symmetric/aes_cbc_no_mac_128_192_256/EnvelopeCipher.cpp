#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

static const size_t AES256_KEY_LEN = 32;   // 256-bit key
static const size_t GCM_IV_LEN     = 12;   // 96-bit nonce per GCM spec

// Initialize an AES-256-GCM encryption context with fresh random key and IV.
// NOTE: In production, supply the key from a secure key management system and
//       ensure each encryption uses a unique IV per key.
struct GcmEncryptCtx {
    EVP_CIPHER_CTX* ctx;
    unsigned char iv[GCM_IV_LEN];
};

static const size_t GCM_TAG_LEN = 16;  // 128-bit tag

static void validate_key_len(size_t key_len) {
    if (key_len != AES256_KEY_LEN) {
        throw std::invalid_argument("AES-256-GCM requires a 32-byte key");
    }
}

static GcmEncryptCtx create_gcm_encrypt_ctx(const unsigned char* key, size_t key_len) {
    if (key == nullptr) {
        throw std::invalid_argument("key must not be null");
    }
    validate_key_len(key_len);

    GcmEncryptCtx out{};
    if (RAND_bytes(out.iv, GCM_IV_LEN) != 1) {
        throw std::runtime_error("RAND_bytes failed for IV");
    }

    out.ctx = EVP_CIPHER_CTX_new();
    if (!out.ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(out.ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(out.ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed (cipher)");
    }
    if (EVP_CIPHER_CTX_ctrl(out.ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1) {
        EVP_CIPHER_CTX_free(out.ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }
    if (EVP_EncryptInit_ex(out.ctx, nullptr, nullptr, key, out.iv) != 1) {
        EVP_CIPHER_CTX_free(out.ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed (key/iv)");
    }

    return out;
}

static void finalize_gcm(EVP_CIPHER_CTX* ctx, unsigned char* tag, size_t tag_len) {
    if (ctx == nullptr || tag == nullptr) {
        throw std::invalid_argument("ctx and tag must not be null");
    }
    int out_len = 0;
    if (EVP_EncryptFinal_ex(ctx, nullptr, &out_len) != 1) {
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag_len), tag) != 1) {
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
    }
}

static void free_gcm_ctx(GcmEncryptCtx& enc) {
    if (enc.ctx) {
        EVP_CIPHER_CTX_free(enc.ctx);
        enc.ctx = nullptr;
    }
}
 

