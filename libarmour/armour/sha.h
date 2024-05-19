#ifndef _ARMOUR_SHA_H
#define _ARMOUR_SHA_H

#include <stdint.h>

#include <openssl/evp.h>

#define SHA3_512_DIGEST_SIZE 64

EVP_MD_CTX *sha3_512_evp(void);
uint8_t *sha3_512(const uint8_t *data, const uint64_t data_size);

#endif /* _ARMOUR_SHA_H */
