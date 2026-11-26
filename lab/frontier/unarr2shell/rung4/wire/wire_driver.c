/* unarr2shell — loopback wire-to-sink driver (synthetic consumer).
 *
 * Accepts one TCP connection on 127.0.0.1, reads the request body into
 * memory, and feeds those bytes to unarr's documented public API:
 * ar_open_memory -> ar_open_tar_archive -> ar_parse_entry ->
 * ar_entry_get_name (the tar_get_name sink).
 *
 * This is a wire-delivery experiment, not a real application caller. It
 * shows that attacker-supplied wire bytes can reach the sink; it does not
 * establish a network-facing consumer or rung 5.
 *
 * Usage: wire_driver <port>
 * Build: cc -fsanitize=address -g -O0 -I<tree> wire_driver.c <libunarr.a> -o wire_driver
 */
#include "unarr.h"
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_WIRE (8u * 1024u * 1024u)

static unsigned char *read_all(int fd, size_t *out_len)
{
    size_t cap = 8192, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf)
        return NULL;
    for (;;) {
        if (len == cap) {
            if (cap >= MAX_WIRE)
                break;
            cap *= 2;
            unsigned char *tmp = realloc(buf, cap);
            if (!tmp) {
                free(buf);
                return NULL;
            }
            buf = tmp;
        }
        ssize_t got = recv(fd, buf + len, cap - len, 0);
        if (got < 0) {
            free(buf);
            return NULL;
        }
        if (got == 0)
            break;
        len += (size_t)got;
    }
    *out_len = len;
    return buf;
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 2;
    }
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0)
        return 3;
    int reuse = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((unsigned short)atoi(argv[1]));
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(server, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(server, 1) < 0)
        return 4;
    int client = accept(server, NULL, NULL);
    if (client < 0)
        return 5;
    size_t len = 0;
    unsigned char *data = read_all(client, &len);
    close(client);
    close(server);
    if (!data)
        return 6;
    fprintf(stderr, "WIRE_BYTES=%zu\n", len);
    fflush(stderr);

    ar_stream *stream = ar_open_memory(data, len);
    if (!stream) {
        free(data);
        return 7;
    }
    ar_archive *ar = ar_open_tar_archive(stream);
    if (!ar) {
        ar_close(stream);
        free(data);
        return 8;
    }
    if (!ar_parse_entry(ar)) {
        ar_close_archive(ar);
        ar_close(stream);
        free(data);
        return 9;
    }
    const char *name = ar_entry_get_name(ar); /* tar_get_name sink */
    printf("entry name: %s\n", name ? name : "(null)");
    fflush(stdout);
    ar_close_archive(ar);
    ar_close(stream);
    free(data);
    return 0;
}
