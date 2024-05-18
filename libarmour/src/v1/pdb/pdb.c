#include "pdb.h"
#include "sha.h"
#include "error.h"
#include "argon2.h"

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static uint8_t *u16_to_le_bytes(const uint16_t value, uint8_t bytes[2]);
static uint8_t *u32_to_le_bytes(const uint32_t value, uint8_t bytes[4]);

/*
 * endian.h isn't a part of the C89 standard, so we cannot use it.
 * We use byte wrapping, because we are reading raw bytes from storage (pDB
 * database), and if it's big endian we need to wrap it.
 */

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define to_host_u16(le_value) (uint16_t)((le_value >> 8) | (le_value << 8))
#define to_host_u32(le_value)                                             \
    (uint32_t)(((le_value >> 24) & 0xff) | ((le_value << 8) & 0xff0000) | \
               ((le_value >> 8) & 0xff00) | ((le_value << 24) & 0xff000000))
#else
#define to_host_u16(le_value) (uint16_t)(le_value)
#define to_host_u32(le_value) (uint32_t)(le_value)
#endif

/*
 * Convert bits to bytes.
 */
#define b2B(bits) ((bits) / 8)

/*
 * Convert integers to little-endian bytes.
 */

static uint8_t *u16_to_le_bytes(const uint16_t value, uint8_t bytes[2]) {
    bytes[0] = (uint8_t)(value);
    bytes[1] = (uint8_t)(value >> 8);
    return bytes;
}

static uint8_t *u32_to_le_bytes(const uint32_t value, uint8_t bytes[4]) {
    bytes[0] = (uint8_t)(value);
    bytes[1] = (uint8_t)(value >> 8);
    bytes[2] = (uint8_t)(value >> 16);
    bytes[3] = (uint8_t)(value >> 24);
    return bytes;
}

/* -------------------------------------------- */

int pDBv1_open(const char *filename) { return open(filename, O_RDWR); }

pDBv1Error pDBv1Header_init(pDBv1Header *header, int fd) {
    if (!header)
        return pDBv1Error_INPUT;

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
        return pDBv1Error_READ;

    memcpy(header->magic, header->_t, 4);
    header->version = to_host_u16(*(uint16_t *)(header->_t + 4));

    if (header->version != pDBv1_VERSION)
        return pDBv1Error_UNSUPPORTED_VERSION;

    header->ZSTD_compression_level = header->_t[6];
    header->Argon2_type            = header->_t[7];
    header->Argon2_time_cost       = to_host_u32(*(uint32_t *)(header->_t + 8));
    header->Argon2_memory_cost = to_host_u32(*(uint32_t *)(header->_t + 12));
    header->psalt_size         = to_host_u32(*(uint32_t *)(header->_t + 16));

    /* uint8_t *psalt; */

    header->psalt = malloc(header->psalt_size);

    if (!header->psalt)
        return pDBv1Error_MEMORY;

    if (read(fd, header->psalt, header->psalt_size) != header->psalt_size) {
        free(header->psalt);
        return pDBv1Error_READ;
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
        return pDBv1Error_READ;

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
        return pDBv1Error_MEMORY;
    }

    if (read(fd, header->metadata, header->metadata_size) !=
        header->metadata_size) {
        free(header->psalt);
        free(header->metadata);
        return pDBv1Error_READ;
    }

    /* uint8_t header_hash_SHA3_512[64]; */

    if (read(fd, header->header_hash_SHA3_512, 64) != 64)
        return pDBv1Error_READ;

    /* int64_t lock_offset; */

    if ((header->lock_offset = lseek(fd, 0, SEEK_CUR)) < 0)
        return pDBv1Error_READ;

    return pDBv1Error_SUCCESS;
}

uint64_t pDBv1Header_size(const pDBv1Header *header) {
    return 4 + b2B(16) + b2B(8 * 2) + b2B(32 * 3) + header->psalt_size +
           b2B(16 * 5) + 64 + b2B(32) + header->metadata_size;
}

pDBv1Error pDBv1Header_check(const pDBv1Header *header, int fd) {
    int64_t old_off;
    uint64_t size;
    uint8_t *digest, *buf;

    uint8_t le[4];

    pDBv1Error e;

    e = pDBv1Error_SUCCESS;

    /* Magic of the file is correct. */
    if (memcmp(pDBv1_MAGIC, header->magic, 4) != 0)
        return pDBv1Error_FORMAT;

    /* Version of the database is supported by the client. */
    if (header->version != pDBv1_VERSION)
        return pDBv1Error_UNSUPPORTED_VERSION;

    /* Database is unlocked. (jump to `lock`) */
    if (pDBv1Lock_get(header, &e, fd) != pDBv1Lock_UNLOCKED)
        return e == pDBv1Error_SUCCESS ? pDBv1Error_LOCKED : e;

    /* SHA3-512 hash of the whole header is valid. (jump to
     * `header_hash_SHA3_512`) */

    if (header->lock_offset < 1)
        return pDBv1Error_READ;

    old_off = lseek(fd, 0, SEEK_CUR);
    size    = pDBv1Header_size(header);

    lseek(fd, header->lock_offset - size - 64,
          SEEK_SET); /* Go back to start of the header, skipping the header
                        hash. */

    buf = malloc(size);

    if (!buf)
        return pDBv1Error_MEMORY;

    read(fd, buf, size);

    lseek(fd, old_off, SEEK_SET);

    digest = pDBv1_sha3_512(buf, size);

    free(buf);

    if (memcmp(header->header_hash_SHA3_512, digest,
               pDBv1_SHA3_512_DIGEST_SIZE) != 0) {
        free(digest);
        return pDBv1Error_INTEGRITY;
    }

    free(digest);

    /* ZSTD compression level is between `0` and `22` (you can safely check if
     * it is below 23 or below or equal to 23, as the value is unsigned). */

    if (header->ZSTD_compression_level > 23)
        return pDBv1Error_VALUE;

    /* Argon2 type exists. */

    if (!pDBv1_argon2_exists(header->Argon2_type))
        return pDBv1Error_VALUE;

    /* Argon2 time cost is at least `3`. */

    if (header->Argon2_time_cost < 3)
        return pDBv1Error_INSECURE;

    /* Argon2 memory cost is at least `65536`. */

    if (header->Argon2_memory_cost < 65536)
        return pDBv1Error_INSECURE;

    /* `psalt_size` is at least `256`, so `psalt` is at least 256 bytes. (2048
     * bits of entropy) */

    if (header->psalt_size < 256)
        return pDBv1Error_INSECURE;

    /* `salt_size` is at least `8` (16 bits of entropy). */

    if (header->salt_size < 8)
        return pDBv1Error_INSECURE;

    /* `authentication_size` is at least `64`. */

    if (header->authentication_size < 64)
        return pDBv1Error_INSECURE;

    /* `keyfile_crypto_passes` is at least `1`. */

    if (header->keyfile_crypto_passes < 1)
        return pDBv1Error_INSECURE;

    /* `chunk_identifier_size` is at least `1`. */

    if (header->chunk_identifier_size < 1)
        return pDBv1Error_VALUE;

    /* `chunk_size` is larger than `chunk_identifier_size`. */

    if (header->chunk_size <= header->chunk_identifier_size)
        return pDBv1Error_VALUE;

    /* SHA3-512 metadata hash is valid. */

    size = b2B(32) + header->metadata_size;
    buf  = malloc(size);

    memcpy(buf, u32_to_le_bytes(header->metadata_size, le), b2B(32));
    memcpy(buf + b2B(32), header->metadata, header->metadata_size);

    digest = pDBv1_sha3_512(buf, size);
    free(buf);

    if (memcmp(header->metadata_hash_SHA3_512, digest,
               pDBv1_SHA3_512_DIGEST_SIZE) != 0) {
        free(digest);
        return pDBv1Error_INTEGRITY;
    }

    free(digest);

    /* The header is valid if all checks passed. */

    return pDBv1Error_SUCCESS;
}

pDBv1Lock pDBv1Lock_get(const pDBv1Header *header, pDBv1Error *error, int fd) {
    int64_t old_off;
    char lock[1];

    if (!error)
        return pDBv1Lock_ERROR;

    if (!header) {
        *error = pDBv1Error_INPUT;
        return pDBv1Lock_ERROR;
    }

    *error = pDBv1Error_SUCCESS;

    old_off = lseek(fd, 0, SEEK_CUR);
    lseek(fd, header->lock_offset, SEEK_SET);

    if (read(fd, lock, 1) != 1) {
        lseek(fd, old_off, SEEK_SET);
        *error = pDBv1Error_READ;
        return pDBv1Lock_ERROR;
    }

    lseek(fd, old_off, SEEK_SET);

    return (pDBv1Lock)lock[0];
}

pDBv1Error pDBv1Header_destroy(pDBv1Header *header) {
    if (!header)
        return pDBv1Error_INPUT;

    free(header->psalt);
    free(header->metadata);

    return pDBv1Error_SUCCESS;
}

int pDBv1_close(int fd) { return close(fd); }
