#include "EnvelopeCipher.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "pwtp/cases/common/Base64.h"

namespace pwtp::cases::symmetric::aes_cbc_no_mac_128_192_256 {

// An envelope is a serialized payload that bundles metadata with ciphertext.

constexpr size_t KEY_BYTES = 32;
constexpr size_t IV_BYTES = 12;

// Converts UTF-8 text into bytes.
static std::vector<unsigned char> toBytes(const std::string& value) {
    return std::vector<unsigned char>(value.begin(), value.end());
}

// Concatenates byte buffers into a single vector.
static std::vector<unsigned char> concat(const std::vector<unsigned char>& a,
                                         const std::vector<unsigned char>& b) {
    std::vector<unsigned char> out;
    out.reserve(a.size() + b.size());
    out.insert(out.end(), a.begin(), a.end());
    out.insert(out.end(), b.begin(), b.end());
    return out;
}

// Initializes key material and instance state.
EnvelopeCipher::EnvelopeCipher() {
    encryption_key_.resize(KEY_BYTES);
    int rc = RAND_bytes(encryption_key_.data(),
                        static_cast<int>(encryption_key_.size()));
    if (rc != 1) {
        throw std::runtime_error("Random key generation failed");
    }
}

// Encrypts the input and returns a base64 payload.
std::string EnvelopeCipher::encrypt(const std::string& value) {
    auto input = toBytes(value);

    auto iv = nextIv(value);
    auto cipherText = encryptBytes(input, iv);
    // Assemble the payload components for encoding.
    auto payload = concat(iv, cipherText);
    return base64Encode(payload);
}

// Returns the IV for this operation.
std::vector<unsigned char> EnvelopeCipher::nextIv(const std::string&) const {
    std::vector<unsigned char> iv(IV_BYTES);
    int rc = RAND_bytes(iv.data(), static_cast<int>(iv.size()));
    if (rc != 1) {
        throw std::runtime_error("Random IV generation failed");
    }
    return iv;
}

// Encrypts the input and returns the ciphertext.
std::vector<unsigned char> EnvelopeCipher::encryptBytes(
    const std::vector<unsigned char>& input, const std::vector<unsigned char>& iv) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Cipher context not available");
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher init failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            static_cast<int>(iv.size()), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Set IV len failed");
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher key/iv init failed");
    }
    std::vector<unsigned char> out(input.size());
    int out_len = 0;
    int total = 0;
    if (EVP_EncryptUpdate(ctx, out.data(), &out_len, input.data(),
                          static_cast<int>(input.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher update failed");
    }
    total += out_len;
    int tmp = 0;
    if (EVP_EncryptFinal_ex(ctx, out.data() + total, &tmp) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher finalize failed");
    }
    total += tmp;
    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(sizeof(tag)), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Get tag failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    out.resize(total);
    std::vector<unsigned char> tagVec(tag, tag + sizeof(tag));
    return concat(out, tagVec);
}

}  // namespace pwtp::cases::symmetric::aes_cbc_no_mac_128_192_256
