#ifndef _PDBv1_SHA_H
#define _PDBv1_SHA_H

#include <stdint.h>

#define pDBv1_SHA3_512_DIGEST_SIZE 64

uint8_t *pDBv1_sha3_512(const uint8_t *data, const uint64_t data_size);

#endif /* _PDBv1_SHA_H */
