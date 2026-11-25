// W187 bounded experiment: does a prior complete large SysEx (which grows the
// stream buffer to MAX_STREAM_BUFFER_SIZE through the safe fragment path)
// leave the parser at capacity 32768 and thereby force a later oversized
// one-shot SysEx onto checkStreamBufferCapacity()'s false branch?
//
// No parser source byte is changed. The 32768-byte allocation is counted by
// an operator new[] override so the two cases are comparable. Under ASan the
// fresh-parser attack must report the known overflow; the preconditioned
// parser must stay clean if capacity persists.
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <unistd.h>

#include "mt32emu.h"

using namespace MT32Emu;

static size_t g_large_allocs = 0;

void *operator new[](size_t n) {
	void *p = malloc(n);
	if (n == 32768) ++g_large_allocs;
	return p;
}
void operator delete[](void *p) throw() { free(p); }
void operator delete[](void *p, size_t) throw() { free(p); }

// Avoid stdio after a possible overflow / forged allocator metadata.
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

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "fresh";
	bool precondition = !strcmp(mode, "precondition");

	Synth synth;
	DefaultMidiStreamParser parser(synth);

	if (precondition) {
		// 32 x 1024 bytes = 32768 total: one complete SysEx, fragmented.
		Bit8u frag[1024];
		memset(frag, 0x5a, sizeof frag);
		frag[0] = 0xF0;
		for (int i = 0; i < 32; ++i) {
			if (i == 31) frag[1023] = 0xF7;
			parser.parseStream(frag, sizeof frag);
		}
		emit("precondition_done large_allocs=%zu\n", g_large_allocs);
	}

	const Bit32u len = 40001;
	Bit8u *stream = new Bit8u[len];
	memset(stream, 0x5a, len);
	stream[0] = 0xF0; // no F7: one-shot incomplete SysEx
	parser.parseStream(stream, len);
	emit("mode=%s len=%u large_allocs=%zu\n", mode, len, g_large_allocs);
	return 0; // no destructor: a possible overflow may have corrupted metadata
}
