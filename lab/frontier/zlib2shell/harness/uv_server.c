/* zlib2shell W3 — bounded rung-5 experiment.
 *
 * Plant-started 127.0.0.1 gzip server. The TCP peer's own request bytes are
 * copied past state->in by gz_vacate() after a stalled gzwrite(). A real
 * libuv async handle, allocated after gz_init() so it sits in the overwritten
 * heap range, has its async_cb field replaced by the peer with libc system().
 * libuv's own event-loop dispatch calls that field with the handle as arg;
 * the handle's first bytes are a short benign peer-chosen shell command.
 *
 * No zlib source is edited. Build with -no-pie so system@plt is fixed.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <uv.h>
#include "zlib.h"

#define REQ_MAX 359400u

static uv_async_t *g_async;

static void real_async_cb(uv_async_t *h) { (void)h; }

static void print_hex(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(void) {
    /* Keep system@plt in the link without executing this branch. */
    if (getenv("ZLIB2_UNUSED_FORCE_PLT")) system("true");

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

    const char *sb = getenv("TCP_SNDBUF");
    int sndbuf = sb ? atoi(sb) : 4096;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof sndbuf);
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) return 2;

    gzFile gz = gzdopen(fd, "wb");
    if (!gz) return 2;

    /* Force gz_init() and the gzip header before the handle exists. */
    unsigned char probe = 0x42;
    gzwrite(gz, &probe, 1);
    gzflush(gz, Z_SYNC_FLUSH);

    /* Allocate the real libuv handle after gz_init()/state->in so the heap
     * overflow can reach it. All fields are printed for peer-byte crafting. */
    uv_loop_t *loop = uv_default_loop();
    g_async = malloc(sizeof *g_async);
    if (!g_async || uv_async_init(loop, g_async, real_async_cb)) return 2;


    printf("SYSTEM_ADDR=%p\n", (void *)&system);
    printf("ASYNC_ADDR=%p\n", (void *)g_async);
    printf("LOOP_ADDR=%p\n", (void *)loop);
    printf("HANDLE_SIZE=%zu\n", sizeof *g_async);
    printf("ASYNC_CB_OFF=%zu\n", offsetof(uv_async_t, async_cb));
    printf("HANDLE_HEX=");
    print_hex((const unsigned char *)g_async, sizeof *g_async);
    fflush(stdout);

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

    /* Real event-loop dispatch of the (peer-rewritten) async callback. */
    uv_async_send(g_async);
    printf("UV_SENT=1\n");
    fflush(stdout);
    uv_run(loop, UV_RUN_ONCE);
    printf("UV_RAN=1\n");
    fflush(stdout);

    gzclose(gz);
    free(req);
    printf("SERVER_DONE=1\n");
    return 0;
}
