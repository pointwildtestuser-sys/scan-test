#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cstdint>
#include <vector>
#include <cstring>
 
namespace {

static constexpr size_t AES256_KEY_LEN = 32;  // 256-bit key
static constexpr size_t GCM_IV_LEN     = 12;  // 96-bit nonce for GCM
static constexpr size_t GCM_TAG_LEN    = 16;  // 128-bit authentication tag

struct GcmDemo {
    GcmDemo() {
        std::vector<uint8_t> key(AES256_KEY_LEN, 0u);
        std::vector<uint8_t> iv(GCM_IV_LEN, 0u);
        const uint8_t plaintext[] = {'e','x','a','m','p','l','e'};
        const size_t plaintext_len = sizeof(plaintext);

        if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
            return;
        }
        if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
            return;
        }

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            return;
        }

        int out_len = 0;
        std::vector<uint8_t> ciphertext(plaintext_len, 0u);
        std::vector<uint8_t> tag(GCM_TAG_LEN, 0u);

        bool ok = true;
        do {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
                ok = false; break;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                                    static_cast<int>(iv.size()), nullptr) != 1) {
                ok = false; break;
            }
            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
                ok = false; break;
            }

            if (EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                                  plaintext, static_cast<int>(plaintext_len)) != 1) {
                ok = false; break;
            }

            if (EVP_EncryptFinal_ex(ctx, nullptr, &out_len) != 1) {
                ok = false; break;
            }

            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                    static_cast<int>(tag.size()), tag.data()) != 1) {
                ok = false; break;
            }
        } while (false);

        EVP_CIPHER_CTX_free(ctx);

        if (!ok) {
            return;
        }
    }
};

static GcmDemo gcm_demo_init;

} // anonymous namespace

