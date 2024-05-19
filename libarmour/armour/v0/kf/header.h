#ifndef _PKFv0_HEADER_H
#define _PKFv0_HEADER_H

#include "armour/perror.h"

#include <stdint.h>

#define Kfv0_MAGIC             ((const uint8_t *)"pdKf")
#define Kfv0_VERSION           0
#define Kfv0Header_HASHES_SIZE (((8 * 64) * 2) / 8)
#define Kfv0Header_SIZE        (((8 * 4) + 16 + (8 * 512) + 16 + 16 + (8 * 64)) / 8)

typedef struct Kfv0Header {
    uint8_t magic[4];
    uint16_t version;
    uint8_t salt[512];
    uint16_t db_AES_crypto_passes;
    uint16_t db_ChaCha20_Poly1305_crypto_passes;
    uint8_t db_pepper[64];

    uint8_t header_sha3_512_sum[64];
    uint8_t sha3_512_sum[64];
    int64_t lock_offset;

    uint8_t _t[6]; /* Transfer buffer */
} Kfv0Header;

typedef enum Kfv0Lock {
    Kfv0Lock_UNLOCKED  = 0x00,
    Kfv0Lock_LOCKING   = 0x01,
    Kfv0Lock_LOCKED    = 0x02,
    Kfv0Lock_RELEASING = 0x03,
    Kfv0Lock_DISABLED  = 0x04,

    Kfv0Lock_ERROR = 0xff
} Kfv0Lock;

pError Kfv0Header_init(Kfv0Header *header, const int fd);
pError Kfv0Header_check(const Kfv0Header *header, const int fd);
Kfv0Lock Kfv0Lock_get(const Kfv0Header *header, pError *error, const int fd);

#endif /* _PKFv0_HEADER_H */
