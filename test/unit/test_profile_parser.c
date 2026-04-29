// SPDX-License-Identifier: GPL-2.0
/*
 * Unit tests for profile_parser.c
 *
 * Tests parse_port_defaults(), profile_load(), and related functions
 * by loading actual YAML profile files and verifying parsed struct values.
 *
 * Does NOT require BPF or root — pure user-space parsing tests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "../../user/loader/profile_parser.h"

/* Minimal test framework (subset of rs_test.h without BPF deps) */
static int rs_tests_run;
static int rs_tests_passed;
static int rs_tests_failed;
static int rs_current_test_failed;

#define RS_TEST(name) static void name(void)

#define RS_ASSERT(cond)                                                         \
    do {                                                                        \
        if (!(cond)) {                                                          \
            printf("[ASSERT] %s:%d: condition failed: %s\n",                    \
                   __FILE__, __LINE__, #cond);                                  \
            rs_current_test_failed = 1;                                         \
        }                                                                       \
    } while (0)

#define RS_ASSERT_EQ(a, b)                                                      \
    do {                                                                        \
        long long __a = (long long)(a);                                         \
        long long __b = (long long)(b);                                         \
        if (__a != __b) {                                                       \
            printf("[ASSERT] %s:%d: expected %s == %s (actual: %lld vs %lld)\n",\
                   __FILE__, __LINE__, #a, #b, __a, __b);                       \
            rs_current_test_failed = 1;                                         \
        }                                                                       \
    } while (0)

#define RS_ASSERT_OK(ret)                                                       \
    do {                                                                        \
        int __ret = (int)(ret);                                                 \
        if (__ret != 0) {                                                       \
            printf("[ASSERT] %s:%d: expected %s == 0 (actual: %d)\n",           \
                   __FILE__, __LINE__, #ret, __ret);                            \
            rs_current_test_failed = 1;                                         \
        }                                                                       \
    } while (0)

#define RS_ASSERT_STR_EQ(a, b)                                                  \
    do {                                                                        \
        if (strcmp((a), (b)) != 0) {                                            \
            printf("[ASSERT] %s:%d: expected \"%s\" == \"%s\"\n",               \
                   __FILE__, __LINE__, (a), (b));                               \
            rs_current_test_failed = 1;                                         \
        }                                                                       \
    } while (0)

#define RS_RUN_TEST(name)                                                       \
    do {                                                                        \
        rs_tests_run++;                                                         \
        rs_current_test_failed = 0;                                             \
        printf("[RUN ] %s\n", #name);                                           \
        name();                                                                 \
        if (rs_current_test_failed) {                                           \
            rs_tests_failed++;                                                  \
            printf("[FAIL] %s\n", #name);                                       \
        } else {                                                                \
            rs_tests_passed++;                                                  \
            printf("[PASS] %s\n", #name);                                       \
        }                                                                       \
    } while (0)

/* Helper: resolve profile path relative to project root */
static const char *project_root = NULL;

static void find_project_root(void)
{
    /* Try to find etc/profiles/ from CWD or parent dirs */
    static char root[1024];
    char cwd[1024];

    if (!getcwd(cwd, sizeof(cwd)))
        return;

    /* Walk up from CWD looking for etc/profiles/ */
    strncpy(root, cwd, sizeof(root) - 1);
    for (int i = 0; i < 5; i++) {
        char test[1200];
        snprintf(test, sizeof(test), "%s/etc/profiles", root);
        if (access(test, F_OK) == 0) {
            project_root = root;
            return;
        }
        /* Go up one level */
        char *slash = strrchr(root, '/');
        if (slash && slash != root)
            *slash = '\0';
        else
            break;
    }
    /* Fallback: assume CWD is project root */
    project_root = cwd;
}

static void profile_path(char *buf, size_t buflen, const char *name)
{
    snprintf(buf, buflen, "%s/etc/profiles/%s", project_root, name);
}

/* ────────────────────────────────────────────────────────────────
 * Test: Load dumb.yaml — no port_defaults, no ports
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_load_dumb_profile)
{
    struct rs_profile p;
    char path[1024];
    profile_path(path, sizeof(path), "dumb.yaml");

    int ret = profile_load(path, &p);
    RS_ASSERT_OK(ret);
    RS_ASSERT_STR_EQ(p.name, "dumb");
    RS_ASSERT_EQ(p.has_port_defaults, 0);
    RS_ASSERT_EQ(p.port_count, 0);
    RS_ASSERT_EQ(p.ingress_count, 1);  /* lastcall */
    RS_ASSERT_EQ(p.egress_count, 1);   /* egress_final */
    RS_ASSERT_EQ(p.settings.mac_learning, 0);
    RS_ASSERT_EQ(p.settings.vlan_enforcement, 0);
    profile_free(&p);
}

/* ────────────────────────────────────────────────────────────────
 * Test: Load l2-unmanaged.yaml — no port_defaults, MAC learning on
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_load_l2_unmanaged_profile)
{
    struct rs_profile p;
    char path[1024];
    profile_path(path, sizeof(path), "l2-unmanaged.yaml");

    int ret = profile_load(path, &p);
    RS_ASSERT_OK(ret);
    RS_ASSERT_STR_EQ(p.name, "l2-unmanaged");
    RS_ASSERT_EQ(p.has_port_defaults, 1);
    RS_ASSERT_EQ(p.port_defaults.mac_learning, 1);
    RS_ASSERT_EQ(p.port_defaults.default_priority, 0);
    RS_ASSERT_EQ(p.settings.mac_learning, 1);
    RS_ASSERT_EQ(p.settings.vlan_enforcement, 0);
    RS_ASSERT(p.ingress_count >= 2);  /* at least l2learn + lastcall */
    profile_free(&p);
}

/* ────────────────────────────────────────────────────────────────
 * Test: Load l2-simple-managed.yaml — has port_defaults
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_load_l2_simple_managed_profile)
{
    struct rs_profile p;
    char path[1024];
    profile_path(path, sizeof(path), "l2-simple-managed.yaml");

    int ret = profile_load(path, &p);
    RS_ASSERT_OK(ret);
    RS_ASSERT_STR_EQ(p.name, "l2-simple-managed");
    RS_ASSERT_EQ(p.settings.vlan_enforcement, 1);
    RS_ASSERT_EQ(p.settings.mac_learning, 1);
    /* port_defaults should be parsed */
    RS_ASSERT_EQ(p.has_port_defaults, 1);
    RS_ASSERT_EQ(p.port_count, 0);  /* no explicit ports section */
    profile_free(&p);
}

/* ────────────────────────────────────────────────────────────────
 * Test: Load l3-full.yaml — port_defaults with trunk mode
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_load_l3_full_port_defaults)
{
    struct rs_profile p;
    char path[1024];
    profile_path(path, sizeof(path), "l3-full.yaml");

    int ret = profile_load(path, &p);
    RS_ASSERT_OK(ret);
    RS_ASSERT_STR_EQ(p.name, "l3-full");

    /* port_defaults */
    RS_ASSERT_EQ(p.has_port_defaults, 1);
    RS_ASSERT_EQ(p.port_defaults.vlan_mode, 2);  /* trunk */
    RS_ASSERT_EQ(p.port_defaults.native_vlan, 1);
    RS_ASSERT_EQ(p.port_defaults.mac_learning, 1);
    RS_ASSERT_EQ(p.port_defaults.default_priority, 1);

    /* allowed_vlans: [1] */
    RS_ASSERT_EQ(p.port_defaults.allowed_vlan_count, 1);
    RS_ASSERT_EQ(p.port_defaults.allowed_vlans[0], 1);

    /* management should be parsed */
    RS_ASSERT_EQ(p.mgmt.enabled, 1);
    RS_ASSERT_EQ(p.mgmt.port, 8080);

    /* pipeline sanity */
    RS_ASSERT(p.ingress_count >= 5);
    RS_ASSERT(p.egress_count >= 2);

    profile_free(&p);
}

/* ────────────────────────────────────────────────────────────────
 * Test: Load all.yaml — verify extends or full pipeline
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_load_all_profile)
{
    struct rs_profile p;
    char path[1024];
    profile_path(path, sizeof(path), "all.yaml");

    int ret = profile_load(path, &p);
    RS_ASSERT_OK(ret);
    RS_ASSERT_STR_EQ(p.name, "all");
    /* all.yaml should have the most modules */
    RS_ASSERT(p.ingress_count >= 5);
    RS_ASSERT(p.egress_count >= 2);
    profile_free(&p);
}

/* ────────────────────────────────────────────────────────────────
 * Test: port_defaults struct defaults (enabled=1, management=1, mac_learning=1)
 * when port_defaults section exists but only has vlan_mode
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_port_defaults_struct_defaults)
{
    struct rs_profile p;
    char path[1024];
    profile_path(path, sizeof(path), "l3-full.yaml");

    int ret = profile_load(path, &p);
    RS_ASSERT_OK(ret);
    RS_ASSERT_EQ(p.has_port_defaults, 1);
    /* These should be set by parse_port_defaults init */
    RS_ASSERT_EQ(p.port_defaults.enabled, 1);
    RS_ASSERT_EQ(p.port_defaults.management, 1);
    profile_free(&p);
}

/* ────────────────────────────────────────────────────────────────
 * Test: profile_load with NULL args returns -EINVAL
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_load_null_args)
{
    struct rs_profile p;
    RS_ASSERT(profile_load(NULL, &p) != 0);
    RS_ASSERT(profile_load("/nonexistent/file.yaml", &p) != 0);
}

/* ────────────────────────────────────────────────────────────────
 * Test: profile_init zeroes everything and sets correct defaults
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_profile_init_defaults)
{
    struct rs_profile p;
    profile_init(&p);

    RS_ASSERT_EQ(p.has_port_defaults, 0);
    RS_ASSERT_EQ(p.port_count, 0);
    RS_ASSERT_EQ(p.ingress_count, 0);
    RS_ASSERT_EQ(p.egress_count, 0);
    RS_ASSERT_EQ(p.settings.mac_learning, 0);
    RS_ASSERT_EQ(p.settings.default_vlan, 1);
    RS_ASSERT_EQ(p.settings.unknown_unicast_flood, 1);
    RS_ASSERT_EQ(p.settings.stats_enabled, 1);
}

/* ────────────────────────────────────────────────────────────────
 * Test: All 5 new profiles load without error
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_all_profiles_load_successfully)
{
    const char *profiles[] = {
        "dumb.yaml", "l2-unmanaged.yaml", "l2-simple-managed.yaml",
        "l3-full.yaml", "all.yaml"
    };

    for (int i = 0; i < 5; i++) {
        struct rs_profile p;
        char path[1024];
        profile_path(path, sizeof(path), profiles[i]);
        int ret = profile_load(path, &p);
        if (ret != 0) {
            printf("[ASSERT] Failed to load %s: %d\n", profiles[i], ret);
            rs_current_test_failed = 1;
        }
        /* Every profile must have a name */
        RS_ASSERT(strlen(p.name) > 0);
        profile_free(&p);
    }
}

/* ────────────────────────────────────────────────────────────────
 * Test: port_defaults vlan_mode enum mapping
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_port_defaults_vlan_modes)
{
    /* We test via l3-full.yaml which uses trunk mode */
    struct rs_profile p;
    char path[1024];
    profile_path(path, sizeof(path), "l3-full.yaml");

    int ret = profile_load(path, &p);
    RS_ASSERT_OK(ret);
    /* trunk = 2 */
    RS_ASSERT_EQ(p.port_defaults.vlan_mode, 2);
    profile_free(&p);

    /* dumb.yaml has no port_defaults, so vlan_mode should be 0 */
    profile_path(path, sizeof(path), "dumb.yaml");
    ret = profile_load(path, &p);
    RS_ASSERT_OK(ret);
    RS_ASSERT_EQ(p.has_port_defaults, 0);
    profile_free(&p);
}

/* ────────────────────────────────────────────────────────────────
 * Test: DHCP snooping parsed correctly in l3-full
 * ──────────────────────────────────────────────────────────────── */
RS_TEST(test_dhcp_snooping_parsing)
{
    struct rs_profile p;
    char path[1024];
    profile_path(path, sizeof(path), "l3-full.yaml");

    int ret = profile_load(path, &p);
    RS_ASSERT_OK(ret);
    RS_ASSERT_EQ(p.dhcp_snooping.enabled, 1);
    RS_ASSERT_EQ(p.dhcp_snooping.drop_rogue_server, 1);
    profile_free(&p);
}

/* ────────────────────────────────────────────────────────────────
 * Main
 * ──────────────────────────────────────────────────────────────── */
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    rs_tests_run = 0;
    rs_tests_passed = 0;
    rs_tests_failed = 0;

    find_project_root();
    if (!project_root) {
        fprintf(stderr, "Cannot find project root (etc/profiles/)\n");
        return 1;
    }
    printf("Project root: %s\n\n", project_root);

    RS_RUN_TEST(test_profile_init_defaults);
    RS_RUN_TEST(test_load_null_args);
    RS_RUN_TEST(test_load_dumb_profile);
    RS_RUN_TEST(test_load_l2_unmanaged_profile);
    RS_RUN_TEST(test_load_l2_simple_managed_profile);
    RS_RUN_TEST(test_load_l3_full_port_defaults);
    RS_RUN_TEST(test_load_all_profile);
    RS_RUN_TEST(test_port_defaults_struct_defaults);
    RS_RUN_TEST(test_all_profiles_load_successfully);
    RS_RUN_TEST(test_port_defaults_vlan_modes);
    RS_RUN_TEST(test_dhcp_snooping_parsing);

    printf("\n%d/%d tests passed\n", rs_tests_passed, rs_tests_run);
    return rs_tests_failed == 0 ? 0 : 1;
}
