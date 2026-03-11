#ifndef RS_TEST_H
#define RS_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <linux/types.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

static int rs_tests_run;
static int rs_tests_passed;
static int rs_tests_failed;
static int rs_current_test_failed;
static const char *rs_test_case_names[512];
static int rs_test_case_failed[512];
static int rs_test_case_count;

#define RS_TEST(name) static void name(void)

struct rs_ctx;
struct rs_test_ctx;

struct rs_test_ctx *rs_test_open(const char *obj_path);
int rs_test_map_insert(struct rs_test_ctx *ctx, const char *map_name, const void *key, const void *value);
int rs_test_run(struct rs_test_ctx *ctx,
                const char *prog_name,
                void *pkt,
                __u32 pkt_size,
                struct rs_ctx *out_ctx,
                __u32 *retval);
void rs_test_close(struct rs_test_ctx *ctx);

#define RS_ASSERT(cond)                                                         \
    do {                                                                        \
        if (!(cond)) {                                                          \
            printf("[ASSERT] %s:%d: condition failed: %s\n",                 \
                   __FILE__, __LINE__, #cond);                                  \
            rs_current_test_failed = 1;                                         \
        }                                                                       \
    } while (0)

#define RS_ASSERT_EQ(a, b)                                                      \
    do {                                                                        \
        long long __a = (long long)(a);                                         \
        long long __b = (long long)(b);                                         \
        if (__a != __b) {                                                       \
            printf("[ASSERT] %s:%d: expected %s == %s (actual: %lld vs %lld)\n", \
                   __FILE__, __LINE__, #a, #b, __a, __b);                       \
            rs_current_test_failed = 1;                                         \
        }                                                                       \
    } while (0)

#define RS_ASSERT_NE(a, b)                                                      \
    do {                                                                        \
        long long __a = (long long)(a);                                         \
        long long __b = (long long)(b);                                         \
        if (__a == __b) {                                                       \
            printf("[ASSERT] %s:%d: expected %s != %s (actual: %lld vs %lld)\n", \
                   __FILE__, __LINE__, #a, #b, __a, __b);                       \
            rs_current_test_failed = 1;                                         \
        }                                                                       \
    } while (0)

#define RS_ASSERT_NEQ(a, b) RS_ASSERT_NE(a, b)

#define RS_ASSERT_OK(ret)                                                       \
    do {                                                                        \
        int __ret = (int)(ret);                                                 \
        if (__ret != 0) {                                                       \
            printf("[ASSERT] %s:%d: expected %s == 0 (actual: %d, errno: %d)\n", \
                   __FILE__, __LINE__, #ret, __ret, errno);                     \
            rs_current_test_failed = 1;                                         \
        }                                                                       \
    } while (0)

#define RS_ASSERT_TRUE(expr) RS_ASSERT((expr))

#define RS_ASSERT_ACTION(retval, expected) RS_ASSERT_EQ((retval), (expected))

static inline void rs_test_record_case(const char *name, int failed)
{
    if (rs_test_case_count >= (int)(sizeof(rs_test_case_names) / sizeof(rs_test_case_names[0])))
        return;
    rs_test_case_names[rs_test_case_count] = name;
    rs_test_case_failed[rs_test_case_count] = failed;
    rs_test_case_count++;
}

static inline void rs_test_report_junit(const char *output_path)
{
    FILE *fp;
    int i;

    if (!output_path)
        return;

    fp = fopen(output_path, "w");
    if (!fp) {
        printf("[WARN] could not write JUnit report to %s: %s\n", output_path, strerror(errno));
        return;
    }

    fprintf(fp,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
            "<testsuite name=\"rswitch-unit\" tests=\"%d\" failures=\"%d\">\n",
            rs_tests_run,
            rs_tests_failed);

    for (i = 0; i < rs_test_case_count; i++) {
        fprintf(fp, "  <testcase name=\"%s\" classname=\"rswitch.unit\">\n", rs_test_case_names[i]);
        if (rs_test_case_failed[i])
            fprintf(fp, "    <failure message=\"assertion failed\"/>\n");
        fprintf(fp, "  </testcase>\n");
    }
    fprintf(fp, "</testsuite>\n");
    fclose(fp);
}

#define RS_RUN_TEST(name)                                                       \
    do {                                                                        \
        rs_tests_run++;                                                         \
        rs_current_test_failed = 0;                                             \
        printf("[RUN ] %s\n", #name);                                         \
        name();                                                                 \
        if (rs_current_test_failed) {                                           \
            rs_tests_failed++;                                                  \
            rs_test_record_case(#name, 1);                                      \
            printf("[FAIL] %s\n", #name);                                     \
        } else {                                                                \
            rs_tests_passed++;                                                  \
            rs_test_record_case(#name, 0);                                      \
            printf("[PASS] %s\n", #name);                                     \
        }                                                                       \
    } while (0)

#define RS_TEST_SUITE_BEGIN()                                                   \
    int main(int argc, char **argv)                                             \
    {                                                                           \
        (void)argc;                                                             \
        (void)argv;                                                             \
        rs_tests_run = 0;                                                       \
        rs_tests_passed = 0;                                                    \
        rs_tests_failed = 0;                                                    \
        rs_test_case_count = 0

#define RS_TEST_SUITE_END()                                                     \
        printf("%d/%d tests passed\n", rs_tests_passed, rs_tests_run);        \
        return rs_tests_failed == 0 ? 0 : 1;                                   \
    }

#endif
