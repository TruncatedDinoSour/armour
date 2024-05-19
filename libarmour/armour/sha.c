#include "sha.h"

#include "null.h"

#include <stdint.h>

#include <openssl/evp.h>

EVP_MD_CTX *sha3_512_evp(void) {
    EVP_MD_CTX *mdctx;

    if ((mdctx = EVP_MD_CTX_new()) == NULL)
        return NULL;

    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha3_512(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }

    return mdctx;
}

uint8_t *sha3_512(const uint8_t *data, const uint64_t data_size) {
    EVP_MD_CTX *mdctx;
    uint8_t *digest;

    if (!(mdctx = sha3_512_evp()))
        return NULL;

    if (1 != EVP_DigestUpdate(mdctx, data, data_size)) {
        EVP_MD_CTX_free(mdctx);
        return NULL;
    }

    digest = malloc(SHA3_512_DIGEST_SIZE);

    if (1 != EVP_DigestFinal_ex(mdctx, digest, NULL)) {
        free(digest);
        return NULL;
    }

    EVP_MD_CTX_free(mdctx);

    return digest;
}
