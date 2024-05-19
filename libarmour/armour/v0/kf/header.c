#include "header.h"

#include "armour/sha.h"
#include "armour/null.h"
#include "armour/perror.h"
#include "armour/endian.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/evp.h>

pError Kfv0Header_init(Kfv0Header *header, const int fd) {
    if (!header || fd < 0)
        return pError_INPUT;

    /*
     * uint8_t magic[4];
     * uint16_t version;
     *
     * (8 * 4) + 16 = 48 bits
     * 48 bits / 8 bits = 6 bytes
     */

    if (read(fd, header->_t, 6) != 6)
        return pError_READ;

    memcpy(header->magic, header->_t, 4);
    header->version = to_host_u16(*(uint16_t *)(header->_t + 4));

    if (header->version != Kfv0_VERSION)
        return pError_UNSUPPORTED_VERSION;

    /* uint8_t salt[512]; */

    if (read(fd, header->salt, 512) != 512)
        return pError_READ;

    /*
     * uint16_t db_AES_crypto_passes;
     * uint16_t db_ChaCha20_Poly1305_crypto_passes;
     *
     * 16 + 16 = 32 bits
     * 32 bits / 8 bits = 4 bytes
     */

    if (read(fd, header->_t, 4) != 4)
        return pError_READ;

    header->db_AES_crypto_passes = to_host_u16(*(uint16_t *)(header->_t + 0));
    header->db_ChaCha20_Poly1305_crypto_passes =
        to_host_u16(*(uint16_t *)(header->_t + 2));

    /*
     * uint8_t db_pepper[64];
     * uint8_t header_sha3_512_sum[64];
     * uint8_t sha3_512_sum[64];
     */

    if (read(fd, header->db_pepper, 64) != 64)
        return pError_READ;

    if (read(fd, header->header_sha3_512_sum, 64) != 64)
        return pError_READ;

    if (read(fd, header->sha3_512_sum, 64) != 64)
        return pError_READ;

    /* int64_t lock_offset; */

    if ((header->lock_offset = lseek(fd, 0, SEEK_CUR)) < 0)
        return pError_READ;

    return pError_SUCCESS;
}

pError Kfv0Header_check(const Kfv0Header *header, const int fd) {
    EVP_MD_CTX *mdctx;

    pError e;

    int64_t old_off;
    int64_t rb;

    uint8_t buf[Kfv0Header_SIZE + Kfv0Header_HASHES_SIZE];
    uint8_t *digest;

    e = pError_SUCCESS;

    if (!header || fd < 0)
        return pError_INPUT;

    /* The magic number of the file is correct. (basic corruption and file type
     * check) */

    if (memcmp(header->magic, Kfv0_MAGIC, 4) != 0)
        return pError_FORMAT;

    /* The version is supported by the target database. (support check) */

    if (header->version != Kfv0_VERSION)
        return pError_UNSUPPORTED_VERSION;

    /* The Keyfile is not currently locked. (access check, to prevent
     * collisions) */

    if (Kfv0Lock_get(header, &e, fd) != Kfv0Lock_UNLOCKED)
        return e == pError_SUCCESS ? pError_LOCKED : e;

    /* `db_AES_crypto_passes` is at least `1`. */

    if (header->db_AES_crypto_passes < 1)
        return pError_INSECURE;

    /* `db_ChaCha20_Poly1305_crypto_passes` is at least `1`. */

    if (header->db_ChaCha20_Poly1305_crypto_passes < 1)
        return pError_INSECURE;

    /* The SHA3-512 sum of the header is correct. (integrity check) */

    old_off = lseek(fd, 0, SEEK_CUR);

    lseek(fd,
          header->lock_offset - (int64_t)Kfv0Header_SIZE -
              (int64_t)Kfv0Header_HASHES_SIZE,
          SEEK_SET); /* Go back to start of the header, skipping the header
                        hashes. */

    if (read(fd, buf, Kfv0Header_SIZE) != Kfv0Header_SIZE) {
        lseek(fd, old_off, SEEK_SET);
        return pError_READ;
    }

    lseek(fd, old_off, SEEK_SET);

    digest = sha3_512(buf, Kfv0Header_SIZE);

    if (!digest)
        return pError_INIT;

    if (memcmp(digest, header->header_sha3_512_sum, SHA3_512_DIGEST_SIZE) !=
        0) {
        free(digest);
        return pError_INTEGRITY;
    }

    free(digest);

    /* The SHA3-512 sum of the database is correct. (integrity check) */

    if (!(mdctx = sha3_512_evp()))
        return pError_INIT;

    lseek(fd, header->lock_offset,
          SEEK_SET); /* Go to the start of the database */

    while ((rb = read(fd, buf, Kfv0Header_SIZE + Kfv0Header_HASHES_SIZE)) > 0)
        if (1 != EVP_DigestUpdate(mdctx, buf, (uint64_t)rb)) {
            lseek(fd, old_off, SEEK_SET);
            EVP_MD_CTX_free(mdctx);
            return pError_INIT;
        }

    lseek(fd, old_off, SEEK_SET);

    digest = malloc(SHA3_512_DIGEST_SIZE);

    if (1 != EVP_DigestFinal_ex(mdctx, digest, NULL)) {
        free(digest);
        return pError_INIT;
    }

    EVP_MD_CTX_free(mdctx);

    if (memcmp(digest, header->sha3_512_sum, SHA3_512_DIGEST_SIZE) != 0) {
        free(digest);
        return pError_INTEGRITY;
    }

    free(digest);

    /* Keyfile *header* is valid. */

    return pError_SUCCESS;
}

Kfv0Lock Kfv0Lock_get(const Kfv0Header *header, pError *error, const int fd) {
    int64_t old_off;
    uint8_t lock;

    if (!error)
        return Kfv0Lock_ERROR;

    if (!header || fd < 0) {
        *error = pError_INPUT;
        return Kfv0Lock_ERROR;
    }

    *error = pError_SUCCESS;
    lock   = 0xff;

    old_off = lseek(fd, 0, SEEK_CUR);
    lseek(fd, header->lock_offset, SEEK_SET);

    if (read(fd, &lock, 1) != 1) {
        lseek(fd, old_off, SEEK_SET);
        *error = pError_READ;
        return Kfv0Lock_ERROR;
    }

    lseek(fd, old_off, SEEK_SET);

    return (Kfv0Lock)lock;
}
