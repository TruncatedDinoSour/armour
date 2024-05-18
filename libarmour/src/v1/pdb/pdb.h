#ifndef _PDBv1_H
#define _PDBv1_H

#include "error.h"

#include <time.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>

#define pDBv1_MAGIC   (const char *)"pDB\xf6"
#define pDBv1_VERSION (uint8_t)1

typedef struct pDBv1Header {
    uint8_t magic[4];
    uint16_t version;
    uint8_t ZSTD_compression_level;
    uint8_t Argon2_type;
    uint32_t Argon2_time_cost;
    uint32_t Argon2_memory_cost;
    uint32_t psalt_size;
    uint8_t *psalt;
    uint16_t salt_size;
    uint16_t authentication_size;
    uint16_t keyfile_crypto_passes;
    uint16_t chunk_identifier_size;
    uint16_t chunk_size;
    uint8_t metadata_hash_SHA3_512[64];
    uint32_t metadata_size;
    uint8_t *metadata;
    uint8_t header_hash_SHA3_512[64];
    int64_t lock_offset; /* Offset of before the lock byte */
    uint8_t _t[78];      /* Buffer to use for transfer of data. */
} pDBv1Header;

typedef enum pDBv1Lock {
    pDBv1Lock_UNLOCKED  = 0x00,
    pDBv1Lock_LOCKING   = 0x01,
    pDBv1Lock_LOCKED    = 0x02,
    pDBv1Lock_RELEASING = 0x03,
    pDBv1Lock_DISABLED  = 0x04,

    pDBv1Lock_ERROR = 0xff
} pDBv1Lock;

int pDBv1_open(const char *filename);

pDBv1Error pDBv1Header_init(pDBv1Header *header, int fd);
uint64_t pDBv1Header_size(const pDBv1Header *header);
pDBv1Error pDBv1Header_check(const pDBv1Header *header, int fd);
pDBv1Lock pDBv1Lock_get(const pDBv1Header *header, pDBv1Error *error, int fd);

pDBv1Error pDBv1Header_destroy(pDBv1Header *header);
int pDBv1_close(int fd);

#endif /* _PDBv1_H */
