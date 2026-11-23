/*
 * W11: neighbour identity + export shim for the second-order timer-heap probe.
 * On the pinned ws.c:1057 realloc(65544), records allocations and reports the
 * caller of the one landing at r+65552 (W5 geometry).  Exports the pointer so
 * the live driver can read _size/_used after ws_read_frame().  No library
 * source changes; all traffic stays on the driver's loopback.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);

void *g_ws_neighbor;
void *g_ws_realloc_ret;
unsigned long long g_ws_next_size_before;
size_t g_ws_neighbor_size;

#define MAXREC 8192
struct alloc_rec { void *ptr; size_t size; void *caller; };
static struct alloc_rec recs[MAXREC];
static unsigned nrec;

static void record(void *p, size_t n, void *caller)
{
	if (!p || nrec >= MAXREC)
		return;
	recs[nrec].ptr = p;
	recs[nrec].size = n;
	recs[nrec].caller = caller;
	nrec++;
}

void *malloc(size_t n)
{
	void *p = __libc_malloc(n);
	record(p, n, __builtin_return_address(0));
	return p;
}

void *calloc(size_t a, size_t b)
{
	void *p = __libc_calloc(a, b);
	record(p, a * b, __builtin_return_address(0));
	return p;
}

void *realloc(void *old, size_t n)
{
	void *p = __libc_realloc(old, n);
	static int fired;

	record(p, n, __builtin_return_address(0));
	if (n == 65544 && p && !fired) {
		Dl_info info;
		unsigned i;
		char *neighbor = (char *)p + 65552;
		fired = 1;
		g_ws_realloc_ret = p;
		g_ws_neighbor = neighbor;
		g_ws_next_size_before = *(unsigned long long *)((char *)p + 65544);
		fprintf(stderr, "TIMER_SHIM ret=%p neighbor=%p next_size_before=%016llx\n",
			p, g_ws_neighbor, g_ws_next_size_before);
		for (i = 0; i < nrec; i++) {
			if (recs[i].ptr != neighbor)
				continue;
			g_ws_neighbor_size = recs[i].size;
			fprintf(stderr, "TIMER_NEIGHBOR_ALLOC idx=%u size=%zu caller=%p\n",
				i, recs[i].size, recs[i].caller);
			if (dladdr(recs[i].caller, &info) && info.dli_fname)
				fprintf(stderr, "TIMER_NEIGHBOR_SYMBOL file=%s offset=0x%lx\n",
					info.dli_fname,
					(unsigned long)((char *)recs[i].caller - (char *)info.dli_fbase));
		}
		for (i = 0; i < nrec; i++) {
			char *q = (char *)recs[i].ptr;
			if (!recs[i].ptr || q <= neighbor || q >= neighbor + 640)
				continue;
			fprintf(stderr, "TIMER_AFTER_ALLOC delta=%td size=%zu caller=%p\n",
				q - neighbor, recs[i].size, recs[i].caller);
			if (dladdr(recs[i].caller, &info) && info.dli_fname)
				fprintf(stderr, "TIMER_AFTER_SYMBOL delta=%td file=%s offset=0x%lx\n",
					q - neighbor, info.dli_fname,
					(unsigned long)((char *)recs[i].caller - (char *)info.dli_fbase));
		}
	}
	return p;
}
