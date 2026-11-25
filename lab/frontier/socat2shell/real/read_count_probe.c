/* socat2shell — reproducible read(2) count-boundary probe.
 *
 * Measures why the SOCKS5 sign-extension count (-1..-5 as size_t) cannot store
 * bytes through the shipped consumer on this host. All sockets are
 * loopback-only AF_UNIX socketpairs; no external system is contacted.
 *
 * Phase "store": 600 bytes are queued. Each count gets a fresh 262-byte reply
 * buffer plus 512 canary bytes so a store can be observed without ASan.
 * Phase "threshold": an empty socket distinguishes EAGAIN (kernel accepted the
 * count) from EFAULT (access_ok rejected the range) without consuming data.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int queued_socket(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return -1; }
    unsigned char payload[600];
    memset(payload, 'A', sizeof(payload));
    if (write(sv[1], payload, sizeof(payload)) != (ssize_t)sizeof(payload)) { perror("write"); return -1; }
    int fl = fcntl(sv[0], F_GETFL, 0);
    if (fl < 0 || fcntl(sv[0], F_SETFL, fl | O_NONBLOCK) < 0) { perror("fcntl"); return -1; }
    return sv[0];
}

static int empty_socket(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) { perror("socketpair"); return -1; }
    int fl = fcntl(sv[0], F_GETFL, 0);
    if (fl < 0 || fcntl(sv[0], F_SETFL, fl | O_NONBLOCK) < 0) { perror("fcntl"); return -1; }
    /* Keep the peer open so an accepted count yields EAGAIN, not EOF. */
    return sv[0];
}

static void store_case(int fd, const char *name, size_t count) {
    unsigned char *buf = malloc(262 + 512);
    if (!buf) exit(2);
    errno = 0;
    ssize_t rc = read(fd, buf, count);
    int err = errno;
    int stored = 0;
    for (size_t i = 262; i < 262 + 512; i++) if (buf[i]) { stored = 1; break; }
    printf("phase=store case=%-9s count=0x%016zx rc=%zd errno=%d store=%d\n",
           name, count, rc, err, stored);
    free(buf);
}

static void threshold_case(int fd, const char *name, size_t count) {
    unsigned char *buf = malloc(262);
    if (!buf) exit(2);
    errno = 0;
    ssize_t rc = read(fd, buf, count);
    printf("phase=threshold case=%-10s count=0x%016zx rc=%zd errno=%d\n",
           name, count, rc, errno);
    free(buf);
}

int main(void) {
    int q = queued_socket();
    if (q < 0) return 2;
    /* The five counts the sign-extended SOCKS5 length byte can produce. */
    store_case(q, "minus1", (size_t)-1);
    store_case(q, "minus3", (size_t)-3);
    store_case(q, "minus126", (size_t)-126);
    store_case(q, "half", SIZE_MAX / 2);
    /* Control: a merely large positive count does store past the reply. */
    store_case(q, "2gb", 0x80000000UL);
    close(q);

    int e = empty_socket();
    if (e < 0) return 2;
    threshold_case(e, "2p62", 1UL << 62);
    threshold_case(e, "maxssize", (size_t)((1UL << 63) - 1));
    threshold_case(e, "minus126", SIZE_MAX - 126);
    close(e);
    return 0;
}
