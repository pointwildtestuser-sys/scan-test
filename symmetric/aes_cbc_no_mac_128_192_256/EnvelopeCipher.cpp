#include "EnvelopeCipher.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <stdexcept>
#include <string>
#include <vector>

#include "pwtp/cases/common/Base64.h"

// NOTE: Base64 must be a real implementation. If pwtp/cases/common/Base64.h
// provides placeholder passthroughs, replace it with a proper Base64 codec.
// STRICT_PQ: No version prefixes are used in the envelope format. Decryptors
// MUST reject legacy inputs explicitly (e.g., those starting with "v1:").
namespace pwtp::cases::symmetric::aes_cbc_no_mac_128_192_256 {

// An envelope is a serialized payload that bundles metadata with ciphertext.

constexpr size_t KEY_BYTES = 32;
constexpr size_t IV_BYTES = 12;
constexpr size_t TAG_BYTES = 16;

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
    if (RAND_bytes(encryption_key_.data(), static_cast<int>(encryption_key_.size())) != 1) {
        throw std::runtime_error("Random key generation failed");
    }
}

// Encrypts the input and returns a base64 payload.
std::string EnvelopeCipher::encrypt(const std::string& value) {
    auto input = toBytes(value);

    auto iv = nextIv(value);
    if (iv.size() != IV_BYTES) {
        throw std::runtime_error("IV length invalid; expected 12 bytes");
    }
    if (encryption_key_.size() != KEY_BYTES) {
        throw std::runtime_error("Key length invalid; expected 32 bytes");
    }
    auto cipherText = encryptBytes(input, iv);
    if (cipherText.size() < TAG_BYTES) {
        throw std::runtime_error("Ciphertext too small; TAG missing");
    }
    // STRICT_PQ: Ciphertext layout is [IV(12) || CT || TAG(16)] with no version prefix.
    // Legacy envelopes like 'v1:' + base64(...) MUST be rejected by decrypt callers.
    // Assemble the payload components for encoding.
    auto payload = concat(iv, cipherText);
    return base64Encode(payload);
}

// Returns the IV for this operation.
std::vector<unsigned char> EnvelopeCipher::nextIv(const std::string&) const {
    std::vector<unsigned char> iv(IV_BYTES);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw std::runtime_error("IV generation failed");
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
        throw std::runtime_error("IV length set failed");
    }
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, encryption_key_.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher key/iv set failed");
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
    if (EVP_EncryptFinal_ex(ctx, out.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Cipher finalize failed");
    }
    total += out_len;
    std::vector<unsigned char> tag(TAG_BYTES);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            static_cast<int>(tag.size()), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Tag retrieval failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    out.resize(total);
    std::vector<unsigned char> out_with_tag = concat(out, tag);
    return out_with_tag;
}

}  // namespace pwtp::cases::symmetric::aes_cbc_no_mac_128_192_256
