#include "armour/perror.h"
#include "armour/v1/pdb/pdb.h"
#include "armour/v1/pdb/header.h"

#include "tests/main.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

Testcase_op_register_type(uint64_t, eq, ==, "%lu");

int Test(void) {
    int fd;

    pDBv1Header header;
    pError error;

    fd = pDBv1_open("f:test.pdb");

    if (fd < 0) {
        perror("pDBv1_open()");
        return 1;
    }

    printf("Opened database: %d. Now initializing the header.\n", fd);

    if ((error = pDBv1Header_init(&header, fd)) != pError_SUCCESS) {
        fprintf(stderr, "Failed initializing the header: %s. Errno: %s.\n",
                pError_to_string(error), strerror(errno));
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

    if ((error = pDBv1Header_check(&header, fd)) != pError_SUCCESS) {
        fprintf(stderr, "Database check failed: %s. Errno: %s\n",
                pError_to_string(error), strerror(errno));
        pDBv1_close(fd);
        pDBv1Header_destroy(&header);
        return 1;
    }

    /* ----------------------------------------------- */

    puts("-------------------");

    puts("Checking (asserting) if the values are the expected values.");

    if (header.lock_offset < 0) {
        fputs("`lock_offset` is a negative number.", stderr);
        pDBv1_close(fd);
        pDBv1Header_destroy(&header);
        return 1;
    }

    Testcase tv[] = {
        Testcase_op_testcase(uint64_t, eq, "ZSTD compression level", 1,
                             header.ZSTD_compression_level, 13),
        Testcase_op_testcase(uint64_t, eq, "Argon2 type", 1, header.Argon2_type,
                             2),
        Testcase_op_testcase(uint64_t, eq, "Argon2 time cost", 1,
                             header.Argon2_time_cost, 3),
        Testcase_op_testcase(uint64_t, eq, "Argon2 memory cost", 1,
                             header.Argon2_memory_cost, 65537),
        Testcase_op_testcase(uint64_t, eq, "Password salt size", 1,
                             header.psalt_size, 275),
        Testcase_op_testcase(uint64_t, eq, "Salt size", 1, header.salt_size,
                             19),
        Testcase_op_testcase(uint64_t, eq, "Authentication size", 1,
                             header.authentication_size, 94),
        Testcase_op_testcase(uint64_t, eq, "Keyfile crypto passes", 1,
                             header.keyfile_crypto_passes, 4),
        Testcase_op_testcase(uint64_t, eq, "Chunk identifier size", 1,
                             header.chunk_identifier_size, 66),
        Testcase_op_testcase(uint64_t, eq, "Chunk size", 1, header.chunk_size,
                             123),
        Testcase_op_testcase(uint64_t, eq, "Metadata size", 1,
                             header.metadata_size, 59),
        Testcase_op_testcase(uint64_t, eq, "Lock offset", 1, header.lock_offset,
                             496),
    };

    Testcase_run_tv(tv, NULL, 0);

    puts("-------------------");

    /* ----------------------------------------------- */

    puts("All checks passed. Freeing all resources.");

    if (pDBv1_close(fd) < 0) {
        perror("pDBv1_close()");
        return 1;
    }

    if ((error = pDBv1Header_destroy(&header)) != pError_SUCCESS) {
        fprintf(stderr, "Failed to destroy the header object: %s. Errno: %s\n",
                pError_to_string(error), strerror(errno));
        return 1;
    }

    return 0;
}
