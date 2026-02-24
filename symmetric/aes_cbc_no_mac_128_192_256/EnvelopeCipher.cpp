#include <stdexcept>
#include <vector>
#include <cstdint>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>

// STRICT_PQ: AES-256-GCM only. Legacy AES-128-CBC/ECB formats are not supported.
static constexpr size_t AES256_KEY_LEN = 32;   // 256-bit key
static constexpr size_t GCM_NONCE_LEN = 12;    // 96-bit nonce for GCM
static constexpr size_t GCM_TAG_LEN = 16;      // 128-bit tag

static void require_ok(bool ok, const char *msg)
{
    if (!ok) {
        throw std::runtime_error(msg);
    }
}

struct EvpCtxDeleter {
    void operator()(EVP_CIPHER_CTX *p) const noexcept
    {
        if (p) {
            EVP_CIPHER_CTX_free(p);
        }
    }
};
using EvpCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCtxDeleter>;

std::vector<uint8_t> aes256gcm_encrypt(const std::vector<uint8_t> &key,
                                       const std::vector<uint8_t> &plaintext,
                                       const std::vector<uint8_t> &aad)
{
    require_ok(key.size() == AES256_KEY_LEN,
               "INVALID_KEY_LENGTH: require 32-byte AES-256-GCM key");

    std::vector<uint8_t> nonce(GCM_NONCE_LEN);
    require_ok(RAND_bytes(nonce.data(), (int)nonce.size()) == 1,
               "NONCE_GEN_FAILED");

    EvpCtxPtr ctx(EVP_CIPHER_CTX_new());
    require_ok(ctx != nullptr, "CTX_ALLOC_FAILED");

    int len = 0;
    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> tag(GCM_TAG_LEN);

    require_ok(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                                  nullptr, nullptr) == 1,
               "ENCRYPT_INIT_FAILED");

    require_ok(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                   (int)nonce.size(), nullptr) == 1,
               "SET_IVLEN_FAILED");

    require_ok(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr,
                                  reinterpret_cast<const unsigned char *>(
                                      key.data()),
                                  reinterpret_cast<const unsigned char *>(
                                      nonce.data())) == 1,
               "ENCRYPT_KEY_IV_FAILED");

    if (!aad.empty()) {
        require_ok(EVP_EncryptUpdate(
                       ctx.get(), nullptr, &len,
                       reinterpret_cast<const unsigned char *>(aad.data()),
                       (int)aad.size()) == 1,
                   "AAD_UPDATE_FAILED");
    }

    require_ok(EVP_EncryptUpdate(
                   ctx.get(),
                   reinterpret_cast<unsigned char *>(ciphertext.data()), &len,
                   reinterpret_cast<const unsigned char *>(
                       plaintext.data()),
                   (int)plaintext.size()) == 1,
               "CT_UPDATE_FAILED");
    int ct_len = len;

    require_ok(EVP_EncryptFinal_ex(ctx.get(),
                                   reinterpret_cast<unsigned char *>(
                                       ciphertext.data()) + ct_len,
                                   &len) == 1,
               "ENCRYPT_FINAL_FAILED");
    ct_len += len;
    ciphertext.resize((size_t)ct_len);

    require_ok(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                                   (int)tag.size(), tag.data()) == 1,
               "GET_TAG_FAILED");

    std::vector<uint8_t> out;
    out.reserve(nonce.size() + ciphertext.size() + tag.size());
    out.insert(out.end(), nonce.begin(), nonce.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

std::vector<uint8_t> aes256gcm_decrypt(const std::vector<uint8_t> &key,
                                       const std::vector<uint8_t> &data,
                                       const std::vector<uint8_t> &aad)
{
    require_ok(key.size() == AES256_KEY_LEN,
               "INVALID_KEY_LENGTH: require 32-byte AES-256-GCM key");

    if (data.size() < (GCM_NONCE_LEN + GCM_TAG_LEN)) {
        throw std::runtime_error(
            "UNSUPPORTED_CIPHERTEXT_FORMAT: STRICT_PQ requires AES-256-GCM");
    }

    std::vector<uint8_t> nonce(data.begin(),
                               data.begin() + (ptrdiff_t)GCM_NONCE_LEN);
    std::vector<uint8_t> tag(data.end() - (ptrdiff_t)GCM_TAG_LEN, data.end());
    std::vector<uint8_t> ciphertext(data.begin() + (ptrdiff_t)GCM_NONCE_LEN,
                                    data.end() - (ptrdiff_t)GCM_TAG_LEN);

    EvpCtxPtr ctx(EVP_CIPHER_CTX_new());
    require_ok(ctx != nullptr, "CTX_ALLOC_FAILED");

    int len = 0;
    std::vector<uint8_t> plaintext(ciphertext.size());

    require_ok(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                                  nullptr, nullptr) == 1,
               "DECRYPT_INIT_FAILED");

    require_ok(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                                   (int)nonce.size(), nullptr) == 1,
               "SET_IVLEN_FAILED");

    require_ok(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr,
                                  reinterpret_cast<const unsigned char *>(
                                      key.data()),
                                  reinterpret_cast<const unsigned char *>(
                                      nonce.data())) == 1,
               "DECRYPT_KEY_IV_FAILED");

    if (!aad.empty()) {
        require_ok(EVP_DecryptUpdate(
                       ctx.get(), nullptr, &len,
                       reinterpret_cast<const unsigned char *>(aad.data()),
                       (int)aad.size()) == 1,
                   "AAD_UPDATE_FAILED");
    }

    require_ok(EVP_DecryptUpdate(
                   ctx.get(),
                   reinterpret_cast<unsigned char *>(plaintext.data()), &len,
                   reinterpret_cast<const unsigned char *>(
                       ciphertext.data()),
                   (int)ciphertext.size()) == 1,
               "PT_UPDATE_FAILED");
    int pt_len = len;

    require_ok(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                                   (int)tag.size(), tag.data()) == 1,
               "SET_TAG_FAILED");

    if (EVP_DecryptFinal_ex(
            ctx.get(),
            reinterpret_cast<unsigned char *>(plaintext.data()) + pt_len,
            &len) != 1) {
        throw std::runtime_error(
            "DECRYPT_FAILED: integrity check failed");
    }

    pt_len += len;
    plaintext.resize((size_t)pt_len);
    return plaintext;
}
 

