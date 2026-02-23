#include "EnvelopeCipher.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "pwtp/cases/common/Base64.h"

namespace pwtp::cases::symmetric::aes_cbc_no_mac_128_192_256 {

// An envelope is a serialized payload that bundles metadata with ciphertext.

constexpr size_t KEY_BYTES = 24;
constexpr size_t IV_BYTES = 16;

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
    RAND_bytes(encryption_key_.data(), static_cast<int>(encryption_key_.size()));
}

// Encrypts the input and returns a base64 payload.
std::string EnvelopeCipher::encrypt(const std::string& value) {
    auto input = toBytes(value);

    auto iv = nextIv(value);
    auto cipherText = encryptBytes(input, iv);
    // Assemble the payload components for encoding.
    auto payload = concat(iv, cipherText);
    return std::string("v1:") + base64Encode(payload);
}

// Returns the IV for this operation.
std::vector<unsigned char> EnvelopeCipher::nextIv(const std::string&) const {
    std::vector<unsigned char> iv(IV_BYTES);
    RAND_bytes(iv.data(), static_cast<int>(iv.size()));
    return iv;
}

// Encrypts the input and returns the ciphertext.
std::vector<unsigned char> EnvelopeCipher::encryptBytes(
    const std::vector<unsigned char>& input, const std::vector<unsigned char>& iv) const {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Cipher context not available");
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), nullptr, encryption_key_.data(), iv.data()) !=
        1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher init failed");
    }
    std::vector<unsigned char> out(input.size() + EVP_CIPHER_block_size(EVP_aes_192_cbc()));
    int out_len = 0;
    int total = 0;
    if (EVP_EncryptUpdate(ctx, out.data(), &out_len, input.data(),
                          static_cast<int>(input.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher update failed");
    }
    total += out_len;
    if (EVP_EncryptFinal_ex(ctx, out.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher finalize failed");
    }
    total += out_len;
    EVP_CIPHER_CTX_free(ctx);
    out.resize(total);
    return out;
}

}  // namespace pwtp::cases::symmetric::aes_cbc_no_mac_128_192_256
