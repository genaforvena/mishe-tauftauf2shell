/* Lab-only wire driver for verbatim MQTT-C v1.1.6 / v1.1.7 src/mqtt.c.
 * No upstream source line is edited. Unlike driver.c, the PAL receive function
 * calls recv() on a real AF_INET/SOCK_STREAM socket connected to a fake broker
 * forked by this same process on 127.0.0.1 (ephemeral port). The broker writes
 * the crafted packet in two delayed chunks; no bytes are preloaded into the
 * client receive buffer. All socket activity is loopback only. */
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

static int g_callback_calls;
static size_t g_topic_size;
static size_t g_message_size;
static int g_pal_recv_calls;
static size_t g_pal_recv_bytes;

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
    if (rv > 0) {
        ++g_pal_recv_calls;
        g_pal_recv_bytes += (size_t)rv;
    }
    printf("PAL_RECV fd=%d rv=%zd bufsz=%zu calls=%d bytes=%zu\n",
           (int)fd, rv, bufsz, g_pal_recv_calls, g_pal_recv_bytes);
    return rv;
}

static void on_publish(void **state, struct mqtt_response_publish *publish)
{
    (void)state;
    ++g_callback_calls;
    g_topic_size = publish->topic_name_size;
    g_message_size = publish->application_message_size;
    /* As in driver.c: deliberately do not dereference application_message. */
}

int main(int argc, char **argv)
{
    static uint8_t sendbuf[256];
    static uint8_t recvbuf[512];
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
        /* MQTT client: connect to the fake broker, then only ever receive. */
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
                      recvbuf, sizeof recvbuf, on_publish) != MQTT_OK) {
            fprintf(stderr, "CLIENT INIT FAILED\n"); _exit(2);
        }
        MQTT_PAL_MUTEX_UNLOCK(&client.mutex); /* CONNECT is skipped */

        /* Two socket reads: the first chunk is an incomplete PUBLISH, the
         * second completes it. No packet bytes are copied into recvbuf here. */
        rv = __mqtt_recv(&client);
        printf("RECV1 rv=%zd error=%d callbacks=%d\n", rv, (int)client.error, g_callback_calls);
        rv = __mqtt_recv(&client);
        printf("RECV2 rv=%zd error=%d callbacks=%d topic_size=%zu message_size=%zu\n",
               rv, (int)client.error, g_callback_calls, g_topic_size, g_message_size);
        close(fd);
        _exit(0);
    }

    /* Fake broker: accept the loopback client and write two delayed chunks. */
    fd = accept(listener, (struct sockaddr *)&addr, &addrlen);
    if (fd < 0) { perror("accept"); return 2; }
    close(listener);
    printf("BROKER accept=127.0.0.1:%d fd=%d\n", port, fd);
    for (i = 0; i < packet_len / 2; ++i) broker_buf[i] = packet[i];
    rv = send(fd, broker_buf, packet_len / 2, 0);
    printf("BROKER send1=%zd\n", rv);
    usleep(50000); /* make the two chunks arrive in distinct recv() calls */
    rv = send(fd, packet + packet_len / 2, packet_len - packet_len / 2, 0);
    printf("BROKER send2=%zd\n", rv);
    close(fd);
    if (waitpid(child, &status, 0) != child) { perror("waitpid"); return 2; }
    printf("WIRE_CHILD_STATUS exited=%d code=%d signal=%d\n",
           WIFEXITED(status), WIFEXITED(status) ? WEXITSTATUS(status) : -1,
           WIFSIGNALED(status) ? WTERMSIG(status) : -1);
    return 0;
}
