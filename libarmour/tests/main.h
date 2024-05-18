#ifndef _LTEST_H
#define _LTEST_H

/*
 * Libarmour testing framework.
 */

#include <stdint.h>

int main(void);
int Test(void);

void printhex(const char *label,
              const uint8_t *value,
              const uint64_t size,
              const uint8_t hexlify);
void printascii(const char *label, const uint8_t *value, const uint64_t size);

#ifdef _RUNTEST
int main(void) { return Test(); }

void printhex(const char *label,
              const uint8_t *value,
              const uint64_t size,
              const uint8_t hexlify) {
    uint64_t idx;

    printf("%s: ", label);

    for (idx = 0; idx < size; ++idx)
        printf(hexlify ? "0x%02x " : "%02x", value[idx]);

    putchar('\n');
}

void printascii(const char *label, const uint8_t *value, const uint64_t size) {
    uint64_t idx;

    printf("%s: ", label);

    for (idx = 0; idx < size; ++idx)
        putchar(value[idx] > 31 && value[idx] < 127 ? value[idx] : '.');

    putchar('\n');
}
#endif /* _RUNTEST */

#endif /* _LTEST_H */
