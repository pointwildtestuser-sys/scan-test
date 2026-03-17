#include <openssl/evp.h>
#include <openssl/rand.h>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <cstring>

static const int AES256_KEY_LEN = 32;   // 256-bit key
static const int GCM_IV_LEN = 12;       // 96-bit nonce per NIST SP 800-38D
static const int GCM_TAG_LEN = 16;      // 128-bit authentication tag

std::vector<unsigned char> encryptAes256Gcm(
    const std::vector<unsigned char> &key,
    const std::vector<unsigned char> &plaintext,
    std::vector<unsigned char> &iv_out,
    std::vector<unsigned char> &tag_out) {
    if (static_cast<int>(key.size()) != AES256_KEY_LEN) {
        throw std::invalid_argument("key must be 32 bytes for AES-256-GCM");
    }

    iv_out.resize(GCM_IV_LEN);
    if (RAND_bytes(iv_out.data(), GCM_IV_LEN) != 1) {
        throw std::runtime_error("RAND_bytes(iv) failed");
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    int outlen = 0;
    int len = 0;

    try {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            throw std::runtime_error("EVP_EncryptInit_ex failed");
        }
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_LEN, nullptr) != 1) {
            throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
        }
        if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv_out.data()) != 1) {
            throw std::runtime_error("EVP_EncryptInit_ex set key/iv failed");
        }

        if (!plaintext.empty()) {
            if (EVP_EncryptUpdate(ctx, ciphertext.data(), &outlen,
                                  plaintext.data(),
                                  static_cast<int>(plaintext.size())) != 1) {
                throw std::runtime_error("EVP_EncryptUpdate failed");
            }
        }

        if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + outlen, &len) != 1) {
            throw std::runtime_error("EVP_EncryptFinal_ex failed");
        }
        outlen += len;
        ciphertext.resize(outlen);

        tag_out.resize(GCM_TAG_LEN);
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag_out.data()) != 1) {
            throw std::runtime_error("EVP_CTRL_GCM_GET_TAG failed");
        }

        EVP_CIPHER_CTX_free(ctx);
    } catch (...) {
        EVP_CIPHER_CTX_free(ctx);
        throw;
    }

    return ciphertext;
}

int main() {
    std::vector<unsigned char> key(AES256_KEY_LEN);
    if (RAND_bytes(key.data(), AES256_KEY_LEN) != 1) {
        std::cerr << "RAND_bytes(key) failed" << std::endl;
        return 1;
    }

    const char *msg = "example plaintext";
    std::vector<unsigned char> plaintext(
        reinterpret_cast<const unsigned char *>(msg),
        reinterpret_cast<const unsigned char *>(msg) + std::strlen(msg));

    std::vector<unsigned char> iv;
    std::vector<unsigned char> tag;

    std::vector<unsigned char> ciphertext =
        encryptAes256Gcm(key, plaintext, iv, tag);

    std::cout << "ciphertext bytes: " << ciphertext.size() << std::endl;
    std::cout << "iv bytes: " << iv.size() << ", tag bytes: " << tag.size() << std::endl;

    return 0;
}
 

