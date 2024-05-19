#include "armour/perror.h"
#include "armour/v0/kf/kf.h"
#include "armour/v0/kf/header.h"

#include "tests/main.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>

Testcase_op_register_type(int64_t, eq, ==, "%ld");

int Test(void) {
    int fd;

    Kfv0Header header = {0};
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

    puts("----------- All checks passed. Freeing resources. -----------");

    if (Kfv0_close(fd) < 0)
        perror("Kfv0_close()");

    return 0;
}
