#include "header.h"

#include "armour/sha.h"
#include "armour/perror.h"
#include "armour/argon2.h"
#include "armour/endian.h"

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

pError pDBv1Header_init(pDBv1Header *header, const int fd) {
    if (!header || fd < 0)
        return pError_INPUT;

    /*
     * uint8_t magic[4];
     * uint16_t version;
     * uint8_t ZSTD_compression_level;
     * uint8_t Argon2_type;
     * uint32_t Argon2_time_cost;
     * uint32_t Argon2_memory_cost;
     * uint32_t psalt_size;
     *
     * (8 * 4) + 16 + (8 * 2) + (32 * 3) = 160 bits
     * 160 bits / 8 bits = 20 bytes
     */

    if (read(fd, header->_t, 20) != 20)
        return pError_READ;

    memcpy(header->magic, header->_t, 4);
    header->version = to_host_u16(*(uint16_t *)(header->_t + 4));

    if (header->version != pDBv1_VERSION)
        return pError_UNSUPPORTED_VERSION;

    header->ZSTD_compression_level = header->_t[6];
    header->Argon2_type            = header->_t[7];
    header->Argon2_time_cost       = to_host_u32(*(uint32_t *)(header->_t + 8));
    header->Argon2_memory_cost = to_host_u32(*(uint32_t *)(header->_t + 12));
    header->psalt_size         = to_host_u32(*(uint32_t *)(header->_t + 16));

    /* uint8_t *psalt; */

    header->psalt = malloc(header->psalt_size);

    if (!header->psalt)
        return pError_MEMORY;

    if (read(fd, header->psalt, header->psalt_size) != header->psalt_size) {
        free(header->psalt);
        return pError_READ;
    }

    /*
     * uint16_t salt_size;
     * uint16_t authentication_size;
     * uint16_t keyfile_crypto_passes;
     * uint16_t chunk_identifier_size;
     * uint16_t chunk_size;
     * uint8_t metadata_hash_SHA3_512[64];
     * uint32_t metadata_size;
     *
     * (16 * 5) + (8 * 64) + 32 = 624 bits
     * 624 bits / 8 bits = 78 bytes
     */

    if (read(fd, header->_t, 78) != 78)
        return pError_READ;

    header->salt_size             = to_host_u16(*(uint16_t *)(header->_t + 0));
    header->authentication_size   = to_host_u16(*(uint16_t *)(header->_t + 2));
    header->keyfile_crypto_passes = to_host_u16(*(uint16_t *)(header->_t + 4));
    header->chunk_identifier_size = to_host_u16(*(uint16_t *)(header->_t + 6));
    header->chunk_size            = to_host_u16(*(uint16_t *)(header->_t + 8));
    memcpy(header->metadata_hash_SHA3_512, header->_t + 10, 64);
    header->metadata_size = to_host_u32(*(uint32_t *)(header->_t + 10 + 64));

    /* uint8_t *metadata; */

    header->metadata = malloc(header->metadata_size);

    if (!header->metadata) {
        free(header->psalt);
        return pError_MEMORY;
    }

    if (read(fd, header->metadata, header->metadata_size) !=
        header->metadata_size) {
        free(header->psalt);
        free(header->metadata);
        return pError_READ;
    }

    /* uint8_t header_hash_SHA3_512[64]; */

    if (read(fd, header->header_hash_SHA3_512, 64) != 64)
        return pError_READ;

    /* int64_t lock_offset; */

    if ((header->lock_offset = lseek(fd, 0, SEEK_CUR)) < 0)
        return pError_READ;

    return pError_SUCCESS;
}

uint64_t pDBv1Header_size(const pDBv1Header *header) {
    if (!header)
        return 0;

    return 4 + b2B(16) + b2B(8 * 2) + b2B(32 * 3) + header->psalt_size +
           b2B(16 * 5) + 64 + b2B(32) + header->metadata_size;
}

pError pDBv1Header_check(const pDBv1Header *header, const int fd) {
    int64_t old_off;
    uint64_t size;
    uint8_t *digest, *buf;

    uint8_t le[4];

    pError e;

    if (!header || fd < 0)
        return pError_INPUT;

    e = pError_SUCCESS;

    /* Magic of the file is correct. */

    if (memcmp(pDBv1_MAGIC, header->magic, 4) != 0)
        return pError_FORMAT;

    /* Version of the database is supported by the client. */

    if (header->version != pDBv1_VERSION)
        return pError_UNSUPPORTED_VERSION;

    /* Database is unlocked. (jump to `lock`) */

    if (pDBv1Lock_get(header, &e, fd) != pDBv1Lock_UNLOCKED)
        return e == pError_SUCCESS ? pError_LOCKED : e;

    /* SHA3-512 hash of the whole header is valid. (jump to
     * `header_hash_SHA3_512`) */

    if (header->lock_offset < 1)
        return pError_READ;

    old_off = lseek(fd, 0, SEEK_CUR);
    size    = pDBv1Header_size(header);

    lseek(fd, header->lock_offset - (int64_t)size - 64,
          SEEK_SET); /* Go back to start of the header, skipping the header
                        hash. */

    buf = malloc(size);

    if (!buf)
        return pError_MEMORY;

    read(fd, buf, size);

    lseek(fd, old_off, SEEK_SET);

    digest = sha3_512(buf, size);

    free(buf);

    if (!digest)
        return pError_INIT;

    if (memcmp(header->header_hash_SHA3_512, digest, SHA3_512_DIGEST_SIZE) !=
        0) {
        free(digest);
        return pError_INTEGRITY;
    }

    free(digest);

    /* ZSTD compression level is between `0` and `22` (you can safely check if
     * it is below 23 or below or equal to 23, as the value is unsigned). */

    if (header->ZSTD_compression_level >= 23)
        return pError_VALUE;

    /* Argon2 type exists. */

    if (!Argon2_exists(header->Argon2_type))
        return pError_VALUE;

    /* Argon2 time cost is at least `3`. */

    if (header->Argon2_time_cost < 3)
        return pError_INSECURE;

    /* Argon2 memory cost is at least `65536`. */

    if (header->Argon2_memory_cost < 65536)
        return pError_INSECURE;

    /* `psalt_size` is at least `256`, so `psalt` is at least 256 bytes. (2048
     * bits of entropy) */

    if (header->psalt_size < 256)
        return pError_INSECURE;

    /* `salt_size` is at least `8` (16 bits of entropy). */

    if (header->salt_size < 8)
        return pError_INSECURE;

    /* `authentication_size` is at least `64`. */

    if (header->authentication_size < 64)
        return pError_INSECURE;

    /* `keyfile_crypto_passes` is at least `1`. */

    if (header->keyfile_crypto_passes < 1)
        return pError_INSECURE;

    /* `chunk_identifier_size` is at least `1`. */

    if (header->chunk_identifier_size < 1)
        return pError_VALUE;

    /* `chunk_size` is larger than `chunk_identifier_size`. */

    if (header->chunk_size <= header->chunk_identifier_size)
        return pError_VALUE;

    /* SHA3-512 metadata hash is valid. */

    size = b2B(32) + header->metadata_size;
    buf  = malloc(size);

    memcpy(buf, u32_to_le_bytes(header->metadata_size, le), b2B(32));
    memcpy(buf + b2B(32), header->metadata, header->metadata_size);

    digest = sha3_512(buf, size);

    free(buf);

    if (!digest)
        return pError_INIT;

    if (memcmp(header->metadata_hash_SHA3_512, digest, SHA3_512_DIGEST_SIZE) !=
        0) {
        free(digest);
        return pError_INTEGRITY;
    }

    free(digest);

    /* The header is valid if all checks passed. */

    return pError_SUCCESS;
}

pDBv1Lock
pDBv1Lock_get(const pDBv1Header *header, pError *error, const int fd) {
    int64_t old_off;
    uint8_t lock;

    if (!error)
        return pDBv1Lock_ERROR;

    if (!header || fd < 0) {
        *error = pError_INPUT;
        return pDBv1Lock_ERROR;
    }

    *error = pError_SUCCESS;
    lock   = 0xff;

    old_off = lseek(fd, 0, SEEK_CUR);
    lseek(fd, header->lock_offset, SEEK_SET);

    if (read(fd, &lock, 1) != 1) {
        lseek(fd, old_off, SEEK_SET);
        *error = pError_READ;
        return pDBv1Lock_ERROR;
    }

    lseek(fd, old_off, SEEK_SET);

    return (pDBv1Lock)lock;
}

pError pDBv1Header_destroy(pDBv1Header *header) {
    if (!header)
        return pError_INPUT;

    free(header->psalt);
    free(header->metadata);

    return pError_SUCCESS;
}
