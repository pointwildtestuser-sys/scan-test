// AES-256-GCM envelope encryption in C++ (OpenSSL EVP)
// - Fresh 96-bit IV per encryption
// - Returns IV, ciphertext, and authentication tag
// - Strict PQ mode: AES-256 only, no legacy formats

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <vector>
#include <cstdlib>

namespace envelope {

static const size_t AES256_KEY_LEN = 32;    // 256-bit key
static const size_t GCM_IV_LEN = 12;        // 96-bit nonce for GCM
static const size_t GCM_TAG_LEN = 16;       // 128-bit tag

struct Ciphertext {
    std::vector<unsigned char> iv;
    std::vector<unsigned char> ct;
    std::vector<unsigned char> tag;
};

static std::vector<unsigned char> base64Decode(const std::string &b64) {
    if (b64.empty()) {
        return {};
    }
    // Allocate sufficient space: 3/4 of input size, rounded up
    std::vector<unsigned char> out((b64.size() * 3) / 4 + 3);
    int len = EVP_DecodeBlock(out.data(),
                              reinterpret_cast<const unsigned char*>(
                                  b64.data()),
                              static_cast<int>(b64.size()));
    if (len < 0) {
        throw std::runtime_error("invalid base64 input for AES key");
    }
    // Adjust for '=' padding
    int padding = 0;
    if (!b64.empty() && b64.back() == '=') {
        padding++;
        if (b64.size() > 1 && b64[b64.size() - 2] == '=') {
            padding++;
        }
    }
    if (len < padding) {
        throw std::runtime_error("base64 padding error");
    }
    out.resize(static_cast<size_t>(len - padding));
    return out;
}

Ciphertext encrypt(const std::vector<unsigned char> &key,
                   const std::vector<unsigned char> &plaintext,
                   const std::vector<unsigned char> &aad = {}) {
    if (key.size() != AES256_KEY_LEN) {
        throw std::runtime_error(
            "AES-256-GCM requires a 256-bit key (32 bytes)");
    }

    Ciphertext result;
    result.iv.resize(GCM_IV_LEN);
    if (RAND_bytes(result.iv.data(), static_cast<int>(result.iv.size())) != 1) {
        throw std::runtime_error("failed to generate random IV");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                                nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                             static_cast<int>(result.iv.size()), nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    ok = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), result.iv.data());
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");
    }

    int out_len = 0;
    if (!aad.empty()) {
        ok = EVP_EncryptUpdate(ctx, nullptr, &out_len, aad.data(),
                               static_cast<int>(aad.size()));
        if (ok != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate (AAD) failed");
        }
    }

    result.ct.resize(plaintext.size());
    ok = EVP_EncryptUpdate(ctx, result.ct.data(), &out_len, plaintext.data(),
                           static_cast<int>(plaintext.size()));
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate (PT) failed");
    }
    int ct_len = out_len;

    ok = EVP_EncryptFinal_ex(ctx, result.ct.data() + ct_len, &out_len);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ct_len += out_len;
    result.ct.resize(static_cast<size_t>(ct_len));

    result.tag.resize(GCM_TAG_LEN);
    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                             static_cast<int>(result.tag.size()),
                             result.tag.data());
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return result;
}

Ciphertext encryptWithEnvKey(const std::vector<unsigned char> &plaintext,
                             const std::vector<unsigned char> &aad = {}) {
    const char *b64 = std::getenv("AES256_KEY");
    if (!b64) {
        throw std::runtime_error(
            "AES256_KEY environment variable (base64) is required");
    }
    std::vector<unsigned char> key = base64Decode(std::string(b64));
    if (key.size() != AES256_KEY_LEN) {
        throw std::runtime_error(
            "AES256_KEY must decode to 32 bytes for AES-256-GCM");
    }
    return encrypt(key, plaintext, aad);
}

} // namespace envelope
