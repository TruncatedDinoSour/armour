#include "armour/perror.h"
#include "armour/v0/kf/kf.h"
#include "armour/v0/kf/header.h"

#include "tests/main.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

static uint8_t test_header(void *arg);
Testcase_op_register_type(int64_t, eq, ==, "%ld");

static int fd;
static Kfv0Header og_header;
static Kfv0Header header;

#define retest_header(expected_error)                                        \
    if ((error = Kfv0Header_check(&header, fd)) == expected_error) {         \
        printf("Header  check failed: %s. Errno: %s. Intended behaviour.\n", \
               pError_to_string(error), strerror(errno));                    \
    } else                                                                   \
        fprintf(stderr, "Header check passed??? Error: %s. Errno: %s.\n",    \
                pError_to_string(error), strerror(errno));                   \
    memcpy(&header, &og_header, sizeof(og_header));                          \
    return error == expected_error

bc(uint8_t, invalid_magic, 0, pError_FORMAT);
bc(uint16_t, unsupported_version, 1, pError_UNSUPPORTED_VERSION);
bc(uint16_t, insecure_aes_crypto_passes, 0, pError_INSECURE);
bc(uint16_t, insecure_chacha20_crypto_passes, 0, pError_INSECURE);
bm(uint8_t, invalid_header_hash, pError_INTEGRITY);
bm(uint8_t, invalid_database_hash, pError_INTEGRITY);

static uint8_t test_header(void *arg) {
    (void)arg;
    return Kfv0Header_check(&header, fd) == pError_SUCCESS;
}

int Test(void) {
    pError error;

    fd = Kfv0_open("f:test.pkf");

    if (fd < 0) {
        perror("Kfv0_open");
        return 1;
    }

    printf("Opened Keyfile: %d. Initializing the header.\n", fd);

    if ((error = Kfv0Header_init(&header, fd)) != pError_SUCCESS) {
        printf("Failed to initialize the header: %s. Errno: %s.\n",
               pError_to_string(error), strerror(errno));
        return 1;
    }

    puts("Keyfile header initialized:");

    /* --------------------------------------------- */

    puts("----------- Identifier -----------");

    printhex("Magic", header.magic, 4, 1);
    printascii("Magic (ASCII dump)", header.magic, 4);
    printf("Version: %u\n", header.version);

    puts("----------- Salt -----------");

    printhex("Salt", header.salt, 512, 0);
    printascii("Salt (ASCII dump)", header.salt, 512);

    puts("----------- Database parameters -----------");

    printf("AES crypto passes: %u\n", header.db_AES_crypto_passes);
    printf("ChaCha20-Poly1305 crypto passes: %u\n",
           header.db_ChaCha20_Poly1305_crypto_passes);
    printhex("Pepper", header.db_pepper, 64, 0);
    printascii("Pepper (ASCII dump)", header.db_pepper, 64);

    puts("----------- Integrity -----------");

    printhex("Header SHA3-512", header.header_sha3_512_sum, 64, 0);
    printhex("Database SHA3-512", header.sha3_512_sum, 64, 0);

    puts("----------- Locking -----------");

    printf("Lock offset: %lu\n", header.lock_offset);

    puts("-------------------------------");

    /* --------------------------------------------- */

    puts("Checking the validity of the header.");

    if ((error = Kfv0Header_check(&header, fd)) != pError_SUCCESS) {
        printf("Failed to validate the header: %s. Errno: %s.\n",
               pError_to_string(error), strerror(errno));
        return 1;
    }

    puts("Copying the header.");

    memcpy(&og_header, &header, sizeof(header));

    /* --------------------------------------------- */

    puts("----------- Expected value checks -----------");

    Testcase tv[] = {
        Testcase_op_testcase(int64_t, eq, "AES crypto passes", 1,
                             header.db_AES_crypto_passes, 9),
        Testcase_op_testcase(int64_t, eq, "ChaCha20-Poly1305 crypto passes", 1,
                             header.db_AES_crypto_passes, 9),
        Testcase_op_testcase(int64_t, eq, "Lock offset", 1, header.lock_offset,
                             714),
    };

    Testcase_run_tv(tv, NULL, 0);

    /* --------------------------------------------- */

    puts("----------- Failing test cases -----------");

    Testcase tf[] = {
        {"Invalid magic", 1, &header.magic, &invalid_magic},
        {"Unsupported version", 1, &header.version, &unsupported_version},
        {"Insecure AES crypto pass count", 1, &header.db_AES_crypto_passes,
         &insecure_aes_crypto_passes},
        {"Insecure ChaCha20-Poly1305 crypto pass count", 1,
         &header.db_ChaCha20_Poly1305_crypto_passes,
         &insecure_chacha20_crypto_passes},
        {"Invalid header hash", 1, &header.header_sha3_512_sum,
         &invalid_header_hash},
        {"Invalid database hash", 1, &header.sha3_512_sum,
         &invalid_database_hash},
    };

    Testcase_run_tv(tf, &test_header, 1);

    /* --------------------------------------------- */

    puts("----------- All checks passed. Freeing resources. -----------");

    if (Kfv0_close(fd) < 0)
        perror("Kfv0_close()");

    return 0;
}
