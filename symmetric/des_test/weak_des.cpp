#include <openssl/des.h>

void encryptBlock(DES_cblock* key, DES_cblock* data) {
    DES_key_schedule schedule;
    DES_set_key_unchecked(key, &schedule);
    DES_ecb_encrypt(data, data, &schedule, DES_ENCRYPT);
}
