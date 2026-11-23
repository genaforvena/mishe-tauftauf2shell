// Isolated real-library probe for munt issue #149 (munt2shell).
//
// Question: can a host that only ever delivers small MIDI stream fragments
// accumulate them into the oversized incomplete-SysEx copy at upstream
// MidiStreamParser.cpp:250, or is the fragment path capped at 32768 bytes?
//
// This is deliberately a separate binary from driver.cpp: driver.cpp and its
// evidence are the witness-replayed rung-1..4 lane and must stay byte-stable.
// No parser code, types or allocator are stubbed here either; Synth and
// MidiStreamParser are the real classes in the pinned CMake static library.
//
// Modes:
//   frag-many      8 x 5000-byte incomplete-SysEx fragments in 8 separate
//                  parseStream() calls (ALSA-sequencer-sized), total 40000.
//                  First fragment starts 0xF0; no fragment contains 0xF7.
//   single-N       one parseStream() call with N bytes, 0xF0 + (N-1)x0x5a,
//                  no 0xF7. N=32768 is the exact-cap control; N=32769 is a
//                  one-byte overflow; N=40001 is the known 7233-byte case.
//
// In plain builds operator new[] adds a 16384-byte observation tail to every
// allocation and records the tail of the 32768-byte parser buffer. That tail
// is a harness observation region, NOT an upstream object or live neighbour.

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "mt32emu.h"

using namespace MT32Emu;

#ifdef REAL_TAIL_PROBE
static unsigned char *g_tail = NULL;
static size_t g_tail_size = 0;
static unsigned long g_alloc_32768 = 0;
void *operator new[](size_t n) {
	void *p = malloc(n + 16384);
	if (p == NULL) return NULL;
	if (n == 32768) {
		++g_alloc_32768;
		g_tail = (unsigned char *)p + 32768;
		g_tail_size = 16384;
		memset(g_tail, 0, g_tail_size);
	}
	return p;
}
void operator delete[](void *p) throw() { free(p); }
void operator delete[](void *p, size_t) throw() { free(p); }
#endif

namespace {

struct CountingParser : MidiStreamParser {
	int sysexCount;
	int debugCount;
	Bit32u lastSysexLength;

	CountingParser() : sysexCount(0), debugCount(0), lastSysexLength(0) {}
protected:
	void handleShortMessage(const Bit32u) {}
	void handleSysex(const Bit8u *, const Bit32u length) {
		++sysexCount;
		lastSysexLength = length;
	}
	void handleSystemRealtimeMessage(const Bit8u) {}
	void printDebug(const char *) { ++debugCount; }
};

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
	const char *mode = argc > 1 ? argv[1] : "frag-many";
	Synth synth;
	CountingParser parser;

	if (0 == strcmp(mode, "frag-many")) {
		const Bit32u fragLen = 5000;
		Bit8u *frag = new Bit8u[fragLen];
		for (int i = 0; i < 8; ++i) {
			memset(frag, 0x5a, fragLen);
			if (i == 0) frag[0] = 0xF0;
			parser.parseStream(frag, fragLen);
		}
		delete[] frag;
		printf("mode=%s fragments=8 fraglen=%u total=%u\n", mode, fragLen, 8u * fragLen);
	} else if (0 == strncmp(mode, "single-", 7)) {
		const Bit32u length = (Bit32u)strtoul(mode + 7, NULL, 10);
		Bit8u *stream = new Bit8u[length];
		memset(stream, 0x5a, length);
		stream[0] = 0xF0;
		parser.parseStream(stream, length);
		delete[] stream;
		printf("mode=%s len=%u\n", mode, length);
	} else {
		printf("mode=%s UNKNOWN\n", mode);
		return 2;
	}

	printf("sysex=%d lastlen=%u debug=%d\n",
		parser.sysexCount, parser.lastSysexLength, parser.debugCount);
	reportTail();
	return 0;
}
