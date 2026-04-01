/*
 * STRICT_PQ: Replace insecure AES-128-ECB (no IV, pattern leakage) with
 * AES-256-GCM (AEAD). No legacy decryption path is supported.
 *
 * Requirements:
 * - 256-bit key
 * - 96-bit (12-byte) nonce per encryption (unique, random)
 * - 128-bit (16-byte) authentication tag
 */

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <vector>
#include <cstddef>

namespace envelope {

static const std::size_t AES256_KEY_LEN = 32;   // 256-bit key
static const std::size_t GCM_NONCE_LEN = 12;    // 96-bit nonce (IV)
static const std::size_t GCM_TAG_LEN = 16;      // 128-bit tag

struct Aes256GcmCiphertext {
    std::vector<unsigned char> nonce;       // 12 bytes
    std::vector<unsigned char> tag;         // 16 bytes
    std::vector<unsigned char> ciphertext;  // N bytes
};

static void ensure_len(const std::vector<unsigned char> &v,
                       std::size_t expected, const char *name) {
    if (v.size() != expected) {
        throw std::invalid_argument("invalid length for " +
                                    std::string(name));
    }
}

Aes256GcmCiphertext aes256gcm_encrypt(
    const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &plaintext,
    const std::vector<unsigned char> &aad = {}) {
    ensure_len(key, AES256_KEY_LEN, "key");

    Aes256GcmCiphertext out;
    out.nonce.resize(GCM_NONCE_LEN);
    out.tag.resize(GCM_TAG_LEN);
    out.ciphertext.resize(plaintext.size());

    if (RAND_bytes(out.nonce.data(), static_cast<int>(out.nonce.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
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
                              static_cast<int>(GCM_NONCE_LEN), nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    ok = EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(),
                            out.nonce.data());
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");
    }

    int len = 0;

    if (!aad.empty()) {
        ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(),
                               static_cast<int>(aad.size()));
        if (ok != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_EncryptUpdate (AAD) failed");
        }
    }

    std::vector<unsigned char> tmp(out.ciphertext.size());
    ok = EVP_EncryptUpdate(ctx, tmp.data(), &len, plaintext.data(),
                           static_cast<int>(plaintext.size()));
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate (PT) failed");
    }

    int total = len;

    ok = EVP_EncryptFinal_ex(ctx, tmp.data() + len, &len);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    total += len;

    out.ciphertext.assign(tmp.begin(), tmp.begin() + total);

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                              static_cast<int>(GCM_TAG_LEN), out.tag.data());
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
    }

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

std::vector<unsigned char> aes256gcm_decrypt(
    const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &nonce,
    const std::vector<unsigned char> &tag,
    const std::vector<unsigned char> &ciphertext,
    const std::vector<unsigned char> &aad = {}) {
    ensure_len(key, AES256_KEY_LEN, "key");
    ensure_len(nonce, GCM_NONCE_LEN, "nonce");
    ensure_len(tag, GCM_TAG_LEN, "tag");

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    int ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr,
                                nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                              static_cast<int>(GCM_NONCE_LEN), nullptr);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    ok = EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex (key/iv) failed");
    }

    int len = 0;

    if (!aad.empty()) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(),
                               static_cast<int>(aad.size()));
        if (ok != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptUpdate (AAD) failed");
        }
    }

    std::vector<unsigned char> plaintext(ciphertext.size());
    ok = EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                           static_cast<int>(ciphertext.size()));
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate (CT) failed");
    }

    ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
                              static_cast<int>(GCM_TAG_LEN),
                              const_cast<unsigned char *>(tag.data()));
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_TAG failed");
    }

    int len_final = 0;
    ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len_final);
    if (ok != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("authentication failed");
    }

    plaintext.resize(static_cast<std::size_t>(len + len_final));
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

} // namespace envelope
 

