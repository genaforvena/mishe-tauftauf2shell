/* Lab-only socket driver for verbatim MQTT-C v1.1.6 / v1.1.7 src/mqtt.c.
 * The publish callback is NOT lab-written: callback.inc is extracted verbatim
 * (awk, no edits) from examples/simple_subscriber.c in the pinned tarball at
 * build time, so the driver exercises the shipped subscriber's real callback
 * body. The socket setup, PAL and main() are lab-only; CONNECT is skipped and
 * a forked fake broker writes the crafted PUBLISH in two loopback chunks.
 * No external host, no command execution. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include "mqtt.h"
#include "callback.inc"  /* verbatim examples/simple_subscriber.c:123-133 */

/* callback.inc line 4 is the memcpy at verbatim simple_subscriber.c:127. */

ssize_t mqtt_pal_sendall(mqtt_pal_socket_handle fd, const void *buf, size_t len, int flags)
{
    (void)fd; (void)buf; (void)flags;
    return (ssize_t)len; /* this driver only receives */
}

ssize_t mqtt_pal_recvall(mqtt_pal_socket_handle fd, void *buf, size_t bufsz, int flags)
{
    ssize_t rv;
    do {
        rv = recv(fd, buf, bufsz, flags);
    } while (rv < 0 && errno == EINTR);
    printf("PAL_RECV fd=%d rv=%zd bufsz=%zu\n", (int)fd, rv, bufsz);
    return rv;
}

int main(int argc, char **argv)
{
    /* Same buffer sizes as the shipped simple_subscriber.c main(). */
    uint8_t sendbuf[2048];
    uint8_t recvbuf[1024];
    struct mqtt_client client;
    uint8_t packet[64], broker_buf[64];
    size_t packet_len = 0;
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof addr;
    struct timeval tv = {5, 0};
    int listener, fd, port, status = 0;
    pid_t child;
    ssize_t rv;
    unsigned i;

    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(30);
    if (argc != 2 || strlen(argv[1]) % 2 != 0 || strlen(argv[1]) > sizeof packet * 2) {
        fprintf(stderr, "usage: %s HEX_PACKET\n", argv[0]);
        return 2;
    }
    for (i = 0; i < strlen(argv[1]); i += 2) {
        unsigned byte;
        if (sscanf(argv[1] + i, "%2x", &byte) != 1) return 2;
        packet[packet_len++] = (uint8_t)byte;
    }
    if (packet_len == 0) return 2;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return 2; }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) < 0 ||
        getsockname(listener, (struct sockaddr *)&addr, &addrlen) < 0 ||
        listen(listener, 1) < 0) {
        perror("bind/listen"); return 2;
    }
    port = ntohs(addr.sin_port);
    if (setsockopt(listener, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0) {
        perror("setsockopt"); return 2;
    }

    child = fork();
    if (child < 0) { perror("fork"); return 2; }
    if (child == 0) {
        close(listener);
        fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) { perror("client socket"); _exit(2); }
        memset(&addr, 0, sizeof addr);
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((uint16_t)port);
        if (connect(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
            perror("connect"); _exit(2);
        }
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) < 0) {
            perror("client setsockopt"); _exit(2);
        }
        printf("CLIENT connect=127.0.0.1:%d fd=%d packet_len=%zu\n", port, fd, packet_len);
        if (mqtt_init(&client, fd, sendbuf, sizeof sendbuf,
                      recvbuf, sizeof recvbuf, publish_callback) != MQTT_OK) {
            fprintf(stderr, "CLIENT INIT FAILED\n"); _exit(2);
        }
        MQTT_PAL_MUTEX_UNLOCK(&client.mutex); /* CONNECT is skipped */

        rv = __mqtt_recv(&client);
        printf("RECV1 rv=%zd error=%d\n", rv, (int)client.error);
        rv = __mqtt_recv(&client);
        printf("RECV2 rv=%zd error=%d\n", rv, (int)client.error);
        close(fd);
        _exit(0);
    }

    fd = accept(listener, (struct sockaddr *)&addr, &addrlen);
    if (fd < 0) { perror("accept"); return 2; }
    close(listener);
    printf("BROKER accept=127.0.0.1:%d fd=%d\n", port, fd);
    for (i = 0; i < packet_len / 2; ++i) broker_buf[i] = packet[i];
    rv = send(fd, broker_buf, packet_len / 2, 0);
    printf("BROKER send1=%zd\n", rv);
    usleep(50000);
    rv = send(fd, packet + packet_len / 2, packet_len - packet_len / 2, 0);
    printf("BROKER send2=%zd\n", rv);
    close(fd);
    if (waitpid(child, &status, 0) != child) { perror("waitpid"); return 2; }
    printf("WIRE_CHILD_STATUS exited=%d code=%d signal=%d\n",
           WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
           WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    return 0;
}
