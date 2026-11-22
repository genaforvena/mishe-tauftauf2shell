/*
 * LD_PRELOAD shim for the plain live WS-tport run.  On the first realloc to
 * 65544 bytes (the pinned ws.c:1057 call), place a 128-byte live neighbour
 * immediately after the returned bbuffer and fill it with 0xC3.  The live
 * driver reads that object back after tport_recv_stream_ws returns.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void *g_ws_realloc_ret = NULL;
void *g_ws_victim = NULL;
unsigned long long g_next_size_before = 0;
static void *(*real_realloc)(void *, size_t);
static void *(*real_malloc)(size_t);

void *realloc(void *ptr, size_t size)
{
	void *r;

	if (!real_realloc) {
		real_realloc = (void *(*)(void *, size_t))dlsym(RTLD_NEXT, "realloc");
		real_malloc = (void *(*)(size_t))dlsym(RTLD_NEXT, "malloc");
	}
	r = real_realloc(ptr, size);
	if (size == 65544 && r && !g_ws_realloc_ret) {
		g_ws_realloc_ret = r;
		/* glibc usable size for a 65544 request is 65544; the next
		 * chunk's size field starts exactly at r+65544. */
		g_next_size_before = *(unsigned long long *)((char *)r + 65544);
		g_ws_victim = real_malloc(128);
		if (g_ws_victim)
			memset(g_ws_victim, 0xC3, 128);
		fprintf(stderr, "VICTIM_PRELOAD ret=%p victim=%p off=%td NEXT_SIZE_BEFORE=%016llx\n",
			r, g_ws_victim,
			g_ws_victim ? (char *)g_ws_victim - (char *)r : -1,
			g_next_size_before);
	}
	return r;
}
