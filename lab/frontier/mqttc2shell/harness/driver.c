/* Lab-only driver for verbatim MQTT-C v1.1.6 / v1.1.7 src/mqtt.c.
 * No upstream line is edited. The PAL functions below are lab stubs: no
 * socket, no broker, no external contact. The crafted PUBLISH packet is
 * placed directly in the client receive buffer to reach __mqtt_recv(). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "mqtt.h"

static int g_callback_calls;
static size_t g_topic_size;
static size_t g_message_size;

ssize_t mqtt_pal_sendall(mqtt_pal_socket_handle fd, const void *buf, size_t len, int flags)
{
    (void)fd; (void)buf; (void)flags;
    return (ssize_t)len;
}

ssize_t mqtt_pal_recvall(mqtt_pal_socket_handle fd, void *buf, size_t bufsz, int flags)
{
    (void)fd; (void)buf; (void)bufsz; (void)flags;
    return 0; /* packet is preloaded in the receive buffer */
}

static void on_publish(void **state, struct mqtt_response_publish *publish)
{
    (void)state;
    ++g_callback_calls;
    g_topic_size = publish->topic_name_size;
    g_message_size = publish->application_message_size;
    /* Deliberately do not dereference application_message: on the attack
     * vector the parser has advanced that pointer far outside the buffer. */
}

int main(int argc, char **argv)
{
    static uint8_t sendbuf[256];
    static uint8_t recvbuf[512];
    struct mqtt_client client;
    struct mqtt_response response;
    uint8_t packet[64];
    size_t packet_len = 0;
    ssize_t rv;
    unsigned i;

    if ((argc != 2 && argc != 3) || strlen(argv[1]) % 2 != 0 ||
        strlen(argv[1]) > sizeof(packet) * 2 ||
        (argc == 3 && strcmp(argv[2], "unpack") != 0)) {
        fprintf(stderr, "usage: %s HEX_PACKET [unpack]\n", argv[0]);
        return 2;
    }
    for (i = 0; i < strlen(argv[1]); i += 2) {
        unsigned byte;
        if (sscanf(argv[1] + i, "%2x", &byte) != 1) return 2;
        packet[packet_len++] = (uint8_t)byte;
    }

    /* State-only mode: call the public unpacker without the receive-loop
     * memmove, so the underflowed size is observed as data, not a crash. */
    if (argc == 3) {
        memset(&response, 0, sizeof response);
        rv = mqtt_unpack_response(&response, packet, packet_len);
        printf("UNPACK rv=%zd topic_size=%u message_size=%zu\n", rv,
               (unsigned)response.decoded.publish.topic_name_size,
               response.decoded.publish.application_message_size);
        return 0;
    }

    if (mqtt_init(&client, -1, sendbuf, sizeof sendbuf,
                  recvbuf, sizeof recvbuf, on_publish) != MQTT_OK) {
        fprintf(stderr, "CLIENT INIT FAILED\n");
        return 2;
    }
    /* mqtt_init leaves the mutex held for CONNECT; this driver skips CONNECT. */
    MQTT_PAL_MUTEX_UNLOCK(&client.mutex);
    memcpy(recvbuf, packet, packet_len);
    client.recv_buffer.curr = recvbuf + packet_len;
    client.recv_buffer.curr_sz = sizeof recvbuf - packet_len;

    rv = __mqtt_recv(&client);
    printf("RECV rv=%zd error=%d callbacks=%d topic_size=%zu message_size=%zu\n",
           rv, (int)client.error, g_callback_calls, g_topic_size, g_message_size);
    return 0;
}
