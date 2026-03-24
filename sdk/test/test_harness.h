// SPDX-License-Identifier: LGPL-2.1-or-later
/* rSwitch Module Test Harness
 *
 * Provides macros for writing unit tests for rSwitch BPF modules.
 * Tests run in user-space using BPF_PROG_TEST_RUN.
 */
#ifndef __RS_TEST_HARNESS_H
#define __RS_TEST_HARNESS_H

#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RS_TEST(name) \
    static void test_##name(void); \
    __attribute__((constructor)) static void register_test_##name(void) { \
        rs_register_test(#name, test_##name); \
    } \
    static void test_##name(void)

#define RS_ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        fprintf(stderr, "FAIL: %s:%d: %s != %s (%ld != %ld)\n", \
                __FILE__, __LINE__, #a, #b, (long)(a), (long)(b)); \
        rs_test_fail(); \
    } \
} while (0)

#define RS_ASSERT_NE(a, b) do { \
    if ((a) == (b)) { \
        fprintf(stderr, "FAIL: %s:%d: %s == %s (%ld)\n", \
                __FILE__, __LINE__, #a, #b, (long)(a)); \
        rs_test_fail(); \
    } \
} while (0)

#define RS_ASSERT_TRUE(cond) RS_ASSERT_NE((cond), 0)
#define RS_ASSERT_FALSE(cond) RS_ASSERT_EQ((cond), 0)

/* Test registry (simple global array) */
#define RS_MAX_TESTS 256
typedef void (*rs_test_fn)(void);

struct rs_test_entry {
    const char *name;
    rs_test_fn func;
};

static struct rs_test_entry __rs_tests[RS_MAX_TESTS];
static int __rs_test_count = 0;
static int __rs_test_failures = 0;

static void rs_register_test(const char *name, rs_test_fn func)
{
    if (__rs_test_count < RS_MAX_TESTS) {
        __rs_tests[__rs_test_count].name = name;
        __rs_tests[__rs_test_count].func = func;
        __rs_test_count++;
    }
}

static void rs_test_fail(void)
{
    __rs_test_failures++;
}

static int rs_run_all_tests(void)
{
    printf("Running %d tests...\n", __rs_test_count);
    for (int i = 0; i < __rs_test_count; i++) {
        int prev_fails = __rs_test_failures;
        printf("  [%d/%d] %s... ", i + 1, __rs_test_count, __rs_tests[i].name);
        __rs_tests[i].func();
        if (__rs_test_failures == prev_fails)
            printf("PASS\n");
        else
            printf("FAIL\n");
    }
    printf("\n%d/%d tests passed\n",
           __rs_test_count - __rs_test_failures, __rs_test_count);
    return __rs_test_failures > 0 ? 1 : 0;
}

#endif /* __RS_TEST_HARNESS_H */
