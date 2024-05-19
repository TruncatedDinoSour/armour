#ifndef _LTEST_H
#define _LTEST_H

/*
 * Libarmour testing framework.
 */

#include <stdio.h>
#include <stdint.h>

typedef struct Testcase {
    const char *label;
    const uint8_t expect;
    void *arg;
    uint8_t (*tester)(void *);
} Testcase;

int main(void);
int Test(void);

void printhex(const char *label,
              const uint8_t *value,
              const uint64_t size,
              const uint8_t hexlify);
void printascii(const char *label, const uint8_t *value, const uint64_t size);

uint8_t Testcase_run(const Testcase *testcases,
                     const uint64_t testcases_count,
                     uint8_t (*hook)(void *),
                     const uint8_t hook_expect);

#define Testcase_run_tv(tv, hook, hook_expect)                  \
    if (!Testcase_run((tv), sizeof(tv) / sizeof((tv)[0]), hook, \
                      hook_expect)) {                           \
        fputs("Not all tests passed.\n", stderr);               \
        return 1;                                               \
    }

#define Testcase_op_register_type(type, name, op, fmt)                    \
    static uint8_t _Testcase_op_##type_##name(void *arg);                 \
    static uint8_t _Testcase_op_##type_##name(void *arg) {                \
        const type *values = (type *)arg;                                 \
        const uint8_t ret  = values[0] op values[1];                      \
        printf(fmt " " #op " " fmt " = %u\n", values[0], values[1], ret); \
        return ret;                                                       \
    }                                                                     \
    const uint8_t defined_Testcase_op_##type_##name = 1

#define Testcase_op_testcase(type, name, label, expect, v1, v2)    \
    {                                                              \
        label, expect, (void *)(&((type[2]){(type)v1, (type)v2})), \
            &_Testcase_op_##type_##name,                           \
    }

/* Byte changers/modifiers */

#define bc(type, name, value, expected_error) \
    static uint8_t name(void *arg);           \
    static uint8_t name(void *arg) {          \
        pError error;                         \
        *(type *)arg = value;                 \
        retest_header(expected_error);        \
    }                                         \
    const uint8_t defined_##name = 1

#define bm(type, name, expected_error) \
    static uint8_t name(void *arg);    \
    static uint8_t name(void *arg) {   \
        pError error;                  \
        ++*(type *)arg;                \
        retest_header(expected_error); \
    }                                  \
    const uint8_t defined_##name = 1

/* #define _RUNTEST */

#ifdef _RUNTEST
int main(void) {
    int ret;

    puts("--- Running test ---");
    ret = Test();
    printf("--- Test returned %d: %s ---\n", ret,
           ret == 0 ? "Passing" : "Failing");

    return ret;
}

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

uint8_t Testcase_run(const Testcase *testcases,
                     const uint64_t testcases_count,
                     uint8_t (*hook)(void *),
                     const uint8_t hook_expect) {
    uint64_t idx;
    uint64_t passing;
    uint8_t ret, hret;

    printf("Running %lu tests...\n", testcases_count);

    passing = 0;

    for (idx = 0; idx < testcases_count; ++idx) {
        puts("+++");

        printf("Test %lu expecting %u: %s\n\033[90m", idx,
               testcases[idx].expect, testcases[idx].label);

        fputs("\033[31m", stderr);

        ret = testcases[idx].tester(testcases[idx].arg);

        fputs("\033[0m", stdout);
        fputs("\033[0m", stderr);

        if (hook && (hret = hook(testcases[idx].arg)) != hook_expect) {
            fprintf(stderr,
                    "\033[31m\033[1mTest's hook %lu failed. Hook returned "
                    "non-%u value %u.\033[0m\n",
                    idx, hook_expect, hret);
            continue;
        }

        if (ret == testcases[idx].expect) {
            printf("Test %lu passed.\n", idx);
            ++passing;
        } else
            fprintf(stderr, "\033[31m\033[1mTest %lu failed. Got: %u\033[0m\n",
                    idx, ret);
    }

    printf("--- %lu/%lu tests passed. ---\n", passing, testcases_count);

    return passing == testcases_count;
}
#endif /* _RUNTEST */

#endif /* _LTEST_H */
