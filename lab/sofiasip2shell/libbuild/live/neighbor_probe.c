/*
 * W5: bounded identity probe for the physical heap neighbour of the
 * reallocated WebSocket frame buffer in the live WS SIP tport run.
 *
 * Interposes glibc allocation entry points and records the caller of each
 * allocation.  On the pinned ws.c:1057 realloc to 65544 bytes, the next
 * chunk's size field starts at r+65544 and its user pointer at r+65552.
 * Look for a recorded allocation at r+65552 and print its caller so the
 * neighbour can be symbolized offline.  No library source is modified and
 * no exploit action is taken; all traffic stays on the driver's loopback.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);

#define MAXREC 8192
struct alloc_rec {
	void *ptr;
	size_t size;
	void *caller;
};
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

static void report_symbol(const char *label, void *caller)
{
	Dl_info info;
	if (!caller)
		return;
	if (dladdr(caller, &info) && info.dli_fname)
		fprintf(stderr, "%s addr=%p file=%s base=%p offset=0x%lx\n",
			label, caller, info.dli_fname, info.dli_fbase,
			(unsigned long)((char *)caller - (char *)info.dli_fbase));
	else
		fprintf(stderr, "%s addr=%p NO_DLADDR\n", label, caller);
}

static void print_bytes(const char *label, const unsigned char *p, size_t n)
{
	size_t i;
	fprintf(stderr, "%s=", label);
	for (i = 0; i < n; i++)
		fprintf(stderr, "%02x", p[i]);
	fprintf(stderr, "\n");
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
		char *neighbor = (char *)p + 65552;
		unsigned i, found = 0, bfound = 0;

		fired = 1;
		fprintf(stderr, "NEIGHBOR_PROBE ret=%p expected_user=%p nrec=%u\n",
			p, (void *)neighbor, nrec);
		for (i = 0; i < nrec; i++) {
			if (recs[i].ptr == neighbor) {
				fprintf(stderr, "NEIGHBOR_ALLOC idx=%u size=%zu caller=%p\n",
					i, recs[i].size, recs[i].caller);
				report_symbol("NEIGHBOR_SYMBOL", recs[i].caller);
				found = 1;
			}
			if (old && recs[i].ptr == old) {
				fprintf(stderr, "BBUF_ALLOC idx=%u size=%zu caller=%p\n",
					i, recs[i].size, recs[i].caller);
				report_symbol("BBUF_SYMBOL", recs[i].caller);
				bfound = 1;
			}
		}
		if (found)
			print_bytes("NEIGHBOR_FIRST8",
				    (const unsigned char *)neighbor, 8);
		fprintf(stderr, "NEIGHBOR_FOUND=%u BBUF_FOUND=%u NEXT_SIZE_BEFORE=%016llx\n",
			found, bfound, *(unsigned long long *)((char *)p + 65544));
	}
	return p;
}
