// EnvelopeCipher.cpp (C++)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <vector>
#include <string>
#include <cctype>
#include <cstdlib>

static const size_t KEY_LENGTH_BYTES = 32;    // AES-256 key size
static const size_t GCM_IV_BYTES = 12;        // 96-bit IV for GCM
static const size_t GCM_TAG_BYTES = 16;       // 128-bit tag

static int hexVal(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static std::vector<unsigned char> decodeHexKey(const char* hex)
{
    if (!hex) {
        throw std::runtime_error("ENVELOPE_KEY is not set");
    }
    std::string s(hex);
    if (s.size() != KEY_LENGTH_BYTES * 2) {
        throw std::runtime_error(
            "invalid key length: require 32 bytes (64 hex chars)");
    }
    std::vector<unsigned char> out(KEY_LENGTH_BYTES);
    for (size_t i = 0; i < KEY_LENGTH_BYTES; ++i) {
        int hi = hexVal(s[2 * i]);
        int lo = hexVal(s[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            throw std::runtime_error("invalid hex in ENVELOPE_KEY");
        }
        out[i] = static_cast<unsigned char>((hi << 4) | lo);
    }
    return out;
}

struct EnvelopeCipherOutput {
    std::vector<unsigned char> iv;
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;
};

static EnvelopeCipherOutput envelopeEncrypt(
    const std::vector<unsigned char>& plaintext)
{
    const char* env = std::getenv("ENVELOPE_KEY");
    std::vector<unsigned char> key = decodeHexKey(env);

    unsigned char iv[GCM_IV_BYTES];
    if (RAND_bytes(iv, static_cast<int>(GCM_IV_BYTES)) != 1) {
        throw std::runtime_error("IV generation failed");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr)
        != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }

    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(GCM_IV_BYTES),
            nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_CTRL_GCM_SET_IVLEN failed");
    }

    if (EVP_EncryptInit_ex(
            ctx, nullptr, nullptr, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex (key/iv) failed");
    }

    std::vector<unsigned char> ciphertext(plaintext.size());
    int outlen = 0;
    if (EVP_EncryptUpdate(
            ctx, ciphertext.data(), &outlen,
            plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    int total = outlen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    ciphertext.resize(static_cast<size_t>(total + outlen));

    std::vector<unsigned char> tag(GCM_TAG_BYTES);
    if (EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(GCM_TAG_BYTES),
            tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get GCM tag");
    }

    EVP_CIPHER_CTX_free(ctx);

    EnvelopeCipherOutput out;
    out.iv.assign(iv, iv + GCM_IV_BYTES);
    out.ciphertext = std::move(ciphertext);
    out.tag = std::move(tag);
    return out;
}

static EnvelopeCipherOutput encryptBuffer(
    const std::vector<unsigned char>& data)
{
    return envelopeEncrypt(data);
}

// Persist or transmit iv + ciphertext + tag together;
// decryption requires all three values.






