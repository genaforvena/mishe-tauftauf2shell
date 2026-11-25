/* Stand-in for the ogs-core symbols used by the real-caller replay. */
#ifndef OGS_CORE_H_REALCALLER
#define OGS_CORE_H_REALCALLER
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define OGS_GNUC_FALLTHROUGH do { } while (0)
#define OGS_ERROR (-1)
#define OGS_OK 0

static void ogs_error(const char *message, ...) { printf("ERROR=%s\n", message); }
static void ogs_free(void *p) { free(p); }
static void ogs_log_hexdump(void) { printf("HEXDUMP-SUPPRESSED\n"); }
static void ogs_assert_true(int ok)
{
    if (!ok) { printf("ASSERT-FAILED\n"); abort(); }
}
#define ogs_assert(x) ogs_assert_true((x) != 0)

static char *ogs_strndup(const char *s, size_t n)
{
    char *p = (char *)malloc(n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

#endif
