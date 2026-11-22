/* Minimal plant-started loopback WebSocket server using the pinned libre.
 * Calls the real websock_accept() path; all traffic stays on 127.0.0.1. */
#include <stdio.h>
#include <re.h>


#define PORT 19015
#define LIFETIME_MS 8000

static struct websock *ws;
static struct http_sock *httpsock;
static struct websock_conn *wsc;
static struct tmr lifetime;

static void timeout_handler(void *arg)
{
	(void)arg;
	re_cancel();
}

static void srv_recv_handler(const struct websock_hdr *hdr, struct mbuf *mb,
			     void *arg)
{
	(void)arg;
	fprintf(stdout, "SRV_RECV opcode=%u len=%zu first=%02x\n",
		hdr->opcode, mbuf_get_left(mb),
		mbuf_get_left(mb) ? mbuf_buf(mb)[0] : 0);
	fflush(stdout);
}

static void srv_close_handler(int err, void *arg)
{
	(void)arg;
	fprintf(stdout, "SRV_CLOSE err=%d\n", err);
	fflush(stdout);
}

static void http_req_handler(struct http_conn *conn,
			     const struct http_msg *msg, void *arg)
{
	int err;

	fprintf(stdout, "HTTP_REQ received\n");
	fflush(stdout);

	err = websock_accept(&wsc, ws, conn, msg, 0,
			     srv_recv_handler, srv_close_handler, NULL);
	fprintf(stdout, "WEBSOCK_ACCEPT_RC=%d\n", err);
	fflush(stdout);
}

int main(void)
{
	struct sa srv;
	int err;

	err = libre_init();
	if (err)
		return 10;

	err = sa_set_str(&srv, "127.0.0.1", PORT);
	if (err)
		return 11;

	err = http_listen(&httpsock, &srv, http_req_handler, NULL);
	if (err)
		return 12;

	err = websock_alloc(&ws, NULL, NULL);
	if (err)
		return 13;

	(void)tcp_sock_local_get(http_sock_tcp(httpsock), &srv);
	fprintf(stdout, "LISTENING=127.0.0.1:%u\n", sa_port(&srv));
	fflush(stdout);

	tmr_start(&lifetime, LIFETIME_MS, timeout_handler, NULL);
	(void)re_main(NULL);
	tmr_cancel(&lifetime);

	mem_deref(wsc);
	mem_deref(ws);
	mem_deref(httpsock);
	libre_close();
	fprintf(stdout, "SERVER_DONE\n");
	fflush(stdout);
	return 0;
}
