#include <armour/v1/pdb/pdb.h>
#include <armour/v1/pdb/error.h>

#include <tests/main.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

int Test(void) {
    int fd;
    uint64_t idx;

    pDBv1Header header;
    pDBv1Error error;

    fd = pDBv1_open("f:test.pdb");

    if (fd < 0) {
        perror("pDBv1_open()");
        return 1;
    }

    printf("Opened database: %d. Now initializing the header.\n", fd);

    if ((error = pDBv1Header_init(&header, fd)) != pDBv1Error_SUCCESS) {
        fprintf(stderr, "Failed initializing the header: %s. Errno: %s.\n",
                pDBv1Error_to_string(error), strerror(errno));
        pDBv1_close(fd);
        return 1;
    }

    puts("Database header initialized:");

    /* ----------------------------------------------- */

    puts("----- Magic -----");

    printhex("Magic", header.magic, 4, 1);
    printascii("Magic (ASCII dump)", header.magic, 4);

    puts("----- Constant values -----");

    printf("Version: %u\n", header.version);
    printf("ZSTD compression level: %u\n", header.ZSTD_compression_level);
    printf("Argon2 type: %u\n", header.Argon2_type);
    printf("Argon2 time cost: %u\n", header.Argon2_time_cost);
    printf("Argon2 memory cost: %u\n", header.Argon2_memory_cost);
    printf("Password salt size: %u\n", header.psalt_size);

    puts("----- Password salt -----");

    printhex("Psalt", header.psalt, header.psalt_size, 0);
    printascii("Psalt (ASCII dump)", header.psalt, header.psalt_size);

    puts("----- Post constant values -----");

    printf("Salt size: %u\n", header.salt_size);
    printf("Authentication size: %u\n", header.authentication_size);
    printf("Keyfile cryptography passes: %u\n", header.keyfile_crypto_passes);
    printf("Chunk identifier size: %u\n", header.chunk_identifier_size);
    printf("Chunk size: %u\n", header.chunk_size);

    puts("----- Metadata -----");

    printhex("Metadata hash (SHA3-512)", header.metadata_hash_SHA3_512, 64, 0);
    printf("Metadata size: %u\n", header.metadata_size);
    printascii("Metadata", header.metadata, header.metadata_size);

    puts("----- Integrity -----");

    printhex("Header hash (SHA3-512)", header.header_hash_SHA3_512, 64, 0);

    puts("----- Locking -----");

    printf("Lock offset: %lu\n", header.lock_offset);

    puts("-------------------");

    /* ----------------------------------------------- */

    puts("Validating database.");

    if ((error = pDBv1Header_check(&header, fd)) != pDBv1Error_SUCCESS) {
        fprintf(stderr, "Database check failed: %s. Errno: %s\n",
                pDBv1Error_to_string(error), strerror(errno));
        pDBv1_close(fd);
        pDBv1Header_destroy(&header);
        return 1;
    }

    /* ----------------------------------------------- */

    puts("-------------------");

    puts("Checking (asserting) if the values are the expected values.");

    uint64_t expected[][2] = {
        {header.ZSTD_compression_level, 13},
        {header.Argon2_type, 2},
        {header.Argon2_time_cost, 3},
        {header.Argon2_memory_cost, 65537},
        {header.psalt_size, 275},
        {header.salt_size, 19},
        {header.authentication_size, 94},
        {header.keyfile_crypto_passes, 4},
        {header.chunk_identifier_size, 66},
        {header.chunk_size, 123},
        {header.metadata_size, 59},
        {header.lock_offset, 496},
    };

    for (idx = 0; idx < sizeof(expected) / sizeof(expected[0]); ++idx) {
        printf("Test %lu: %lu == %lu\n", idx, expected[idx][0], expected[idx][1]);

        if (expected[idx][0] != expected[idx][1]) {
            fputs("Previous condition failed.\n", stderr);
            return 1;
        }
    }

    puts("-------------------");

    /* ----------------------------------------------- */

    puts("All checks passed. Freeing all resources.");

    if (pDBv1_close(fd) < 0) {
        perror("pDBv1_close()");
        return 1;
    }

    if ((error = pDBv1Header_destroy(&header)) != pDBv1Error_SUCCESS) {
        fprintf(stderr, "Failed to destroy the header object: %s. Errno: %s\n",
                pDBv1Error_to_string(error), strerror(errno));
        return 1;
    }

    return 0;
}
