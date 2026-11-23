// Real-libmt32emu host driver for munt issue #149 (munt2shell).
// Compiles against the unmodified pinned library source (vuln tree) or the
// tree with pinned fix 1749f7f applied (fixed tree). No parser code, types or
// allocator are stubbed: Synth and DefaultMidiStreamParser are the real
// classes from mt32emu/src, built by the project's own CMake target.
//
// Modes:
//   default-attack   DefaultMidiStreamParser::parseStream(), 40001-byte
//                    incomplete SysEx (0xF0 + 40000 x 0x5a, no 0xF7)
//   default-baseline same parser, 102-byte terminated SysEx
//   count-attack     MidiStreamParser subclass counts dispatched messages
//   count-baseline   102-byte terminated SysEx, dispatch counted
//   count-fragment   101-byte incomplete SysEx, dispatch counted
//
// In plain (non-ASan) builds operator new[] is replaced with malloc(n +
// 16384); the tail of the 32768-byte parser allocation is inspected after
// parseStream returns. That tail is a harness observation region, NOT an
// upstream object or a live allocator neighbour. ASan builds use the real
// allocator and abort at the write.

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "mt32emu.h"
#include "c_interface/c_interface.h"

using namespace MT32Emu;

#ifdef REAL_TAIL_PROBE
static unsigned char *g_tail = NULL;
static size_t g_tail_size = 0;
static unsigned long g_alloc_32768 = 0;
void *operator new[](size_t n) {
	void *p = malloc(n + 16384);
	if (n == 32768) {
		++g_alloc_32768;
		g_tail = static_cast<unsigned char *>(p) + n;
		g_tail_size = 16384;
	}
	return p;
}
void operator delete[](void *p) throw() { free(p); }
void operator delete[](void *p, size_t) throw() { free(p); }
#endif

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

void fillStream(Bit8u *buf, Bit32u length, bool terminated) {
	memset(buf, 0x5a, length);
	buf[0] = 0xF0;
	if (terminated) buf[length - 1] = 0xF7;
}

void reportTail() {
#ifdef REAL_TAIL_PROBE
	size_t chosen = 0;
	for (size_t i = 0; i < g_tail_size; ++i)
		if (g_tail[i] == 0x5a) ++chosen;
	printf("alloc32768=%lu tail_bytes=", g_alloc_32768);
	for (size_t i = 0; i < 16; ++i) printf("%02x", g_tail ? g_tail[i] : 0);
	printf(" tail_0x5a=%zu/%zu\n", chosen, g_tail_size);
#else
	printf("tail_probe=disabled(ASan)\n");
#endif
}

} // namespace

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "default-attack";
	const bool completeAfter = 0 == strcmp(mode, "count-attack-complete");
	const bool attack = completeAfter || 0 == strcmp(mode, "count-attack") ||
		0 == strcmp(mode, "default-attack") || 0 == strcmp(mode, "capi-attack");
	const bool useDefault = 0 == strncmp(mode, "default-", 8);
	const bool useCapi = 0 == strncmp(mode, "capi-", 5);
	const Bit32u length = attack ? 40001u : (0 == strcmp(mode, "count-fragment") ? 101u : 102u);
	const bool terminated = !attack && 0 != strcmp(mode, "count-fragment");

	Bit8u *stream = new Bit8u[length];
	fillStream(stream, length, terminated);

	if (useCapi) {
		mt32emu_report_handler_i rh = {0};
		mt32emu_context ctx = mt32emu_create_context(rh, NULL);
		mt32emu_parse_stream(ctx, stream, length);
		printf("mode=%s len=%u parsed=capi\n", mode, length);
		mt32emu_free_context(ctx);
	} else {
		Synth synth;
		if (useDefault) {
			DefaultMidiStreamParser parser(synth);
			parser.parseStream(stream, length);
			printf("mode=%s len=%u parsed=default\n", mode, length);
		} else {
			CountingParser parser;
			parser.parseStream(stream, length);
			if (completeAfter) {
				const Bit8u end = 0xF7;
				parser.parseStream(&end, 1);
			}
			printf("mode=%s len=%u sysex=%d lastlen=%u short=%d realtime=%d debug=%d\n",
				mode, length, parser.sysexCount, parser.lastSysexLength,
				parser.shortCount, parser.realtimeCount, parser.debugCount);
		}
	}
	reportTail();
	delete[] stream;
	return 0;
}
