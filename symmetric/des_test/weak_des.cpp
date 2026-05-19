#include <openssl/evp.h>
#include <cstddef>
#include <cstdint>

static const size_t AES256_KEY_BYTES = 32;
static const size_t GCM_NONCE_BYTES = 12;
static const size_t GCM_TAG_BYTES = 16;

// AES-256-GCM authenticated encryption.
// - key32: 32-byte key
// - nonce12: 12-byte unique nonce per encryption
// - in: plaintext input of length in_len
// - out: ciphertext output buffer (must be at least in_len bytes)
// - tag16: output buffer for 16-byte authentication tag
// Returns true on success, false on failure.
bool encryptBlock(const unsigned char *key32,
                  const unsigned char *nonce12,
                  const unsigned char *in, int in_len,
                  unsigned char *out, unsigned char *tag16) {
    if (!key32 || !nonce12 || !in || !out || !tag16) {
        return false;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return false;
    }

    int ok = 1;
    int len = 0;
    int ciphertext_len = 0;

    if (ok) ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                     (int)GCM_NONCE_BYTES, NULL) == 1;
    if (ok) ok = EVP_EncryptInit_ex(ctx, NULL, NULL, key32, nonce12) == 1;
    if (ok) ok = EVP_EncryptUpdate(ctx, out, &len, in, in_len) == 1;
    if (ok) ciphertext_len = len;
    if (ok) ok = EVP_EncryptFinal_ex(ctx, out + ciphertext_len, &len) == 1;
    if (ok) ciphertext_len += len;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                                     (int)GCM_TAG_BYTES, tag16) == 1;

    EVP_CIPHER_CTX_free(ctx);
    return ok == 1;
}
