// W171 SYNTHETIC loopback wire-input lane for munt issue #149.
// A one-shot 127.0.0.1 TCP consumer reads one wire block and forwards it in
// ONE DefaultMidiStreamParser::parseStream() call to the real pinned
// libmt32emu static library. No parser method, interface or library type is
// stubbed. This is a synthetic host: it establishes wire-derived rung 4
// mechanics only, not a real network service or rung 5.
//
// In the plain build (-DWIRE_VICTIM), global operator new[] places a live
// host-side Victim object immediately after the library's 32768-byte
// streamBuffer allocation, so the chosen-byte tail can be read back in an
// object that was alive during the call and is read before destruction.
// ASan builds leave the real allocator in place and report the fault.
//
// Usage: wire_driver PORTFILE
//   writes the bound loopback port to PORTFILE, then accepts one connection,
//   reads to EOF, calls parseStream once and reports the result on stdout.

#include <cstdint>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/mman.h>

#include "mt32emu.h"

using namespace MT32Emu;

namespace {

unsigned char g_target[64]; // valid pointee for the victim's initial pointer

#ifdef WIRE_VICTIM
struct alignas(16) Victim {
	unsigned char prefix[8];
	uintptr_t ptr;
	uint32_t magic;
	unsigned char suffix[8];
};

Victim g_initial;
Victim *g_victim = NULL;
void *g_buffer_block = NULL;

void initVictim(Victim *v) {
	memset(v->prefix, 0x11, sizeof v->prefix);
	v->ptr = reinterpret_cast<uintptr_t>(g_target);
	v->magic = 0xcafebabeu;
	memset(v->suffix, 0x22, sizeof v->suffix);
}

void printInitial() {
	printf("initial_victim prefix=%02x%02x ptr=0x%016lx magic=0x%08x suffix=%02x%02x\n",
		g_initial.prefix[0], g_initial.prefix[1],
		(unsigned long)g_initial.ptr, g_initial.magic,
		g_initial.suffix[0], g_initial.suffix[1]);
}

void printVictim(const char *when) {
	if (!g_victim) return;
	printf("%s_victim prefix=%02x%02x ptr=0x%016lx magic=0x%08x suffix=%02x%02x\n",
		when, g_victim->prefix[0], g_victim->prefix[1],
		(unsigned long)g_victim->ptr, g_victim->magic,
		g_victim->suffix[0], g_victim->suffix[1]);
}
#endif

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

} // namespace
#ifdef WIRE_VICTIM
// Dedicated mmap arena: the 7233-byte tail must not touch glibc chunk
// metadata, otherwise the process aborts on free before the victim readback.
// The arena is intentionally never freed; the process exits after reporting.
void *operator new[](size_t n) {
	if (n == 32768 && !g_victim) {
		void *p = mmap(NULL, 1048576, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) abort();
		g_victim = new (static_cast<unsigned char *>(p) + n) Victim;
		initVictim(g_victim);
		g_initial = *g_victim;
		g_buffer_block = p;
		return p;
	}
	void *p = malloc(n);
	if (!p) abort();
	return p;
}
void operator delete[](void *p) throw() {
	if (p != g_buffer_block) free(p);
}
void operator delete[](void *p, size_t) throw() {
	if (p != g_buffer_block) free(p);
}
#endif
int main(int argc, char **argv) {
	setvbuf(stdout, NULL, _IONBF, 0);
	if (argc < 2) {
		fprintf(stderr, "usage: %s PORTFILE\n", argv[0]);
		return 2;
	}
	const int listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener < 0) { perror("socket"); return 2; }
	int one = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof addr);
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	addr.sin_port = 0;
	if (bind(listener, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 2; }
	if (listen(listener, 1) < 0) { perror("listen"); return 2; }
	socklen_t alen = sizeof addr;
	if (getsockname(listener, (struct sockaddr *)&addr, &alen) < 0) { perror("getsockname"); return 2; }
	const unsigned short port = ntohs(addr.sin_port);
	FILE *pf = fopen(argv[1], "w");
	if (!pf) { perror("portfile"); return 2; }
	fprintf(pf, "%u\n", (unsigned)port);
	fclose(pf);
	printf("listen=127.0.0.1:%u\n", (unsigned)port);
	fflush(stdout);

	const int conn = accept(listener, NULL, NULL);
	if (conn < 0) { perror("accept"); return 2; }
	std::vector<Bit8u> wire;
	Bit8u chunk[4096];
	for (;;) {
		const ssize_t got = read(conn, chunk, sizeof chunk);
		if (got < 0) { perror("read"); close(conn); return 2; }
		if (got == 0) break;
		wire.insert(wire.end(), chunk, chunk + got);
		if (wire.size() > 1048576) break;
	}
	close(conn);
	close(listener);
	printf("wire_bytes=%zu first=%02x last=%02x\n", wire.size(),
		wire.empty() ? 0 : wire[0], wire.empty() ? 0 : wire.back());

	CountingParser parser;
	parser.parseStream(wire.empty() ? NULL : &wire[0], (Bit32u)wire.size());
	printf("parse sysex=%d lastlen=%u short=%d realtime=%d debug=%d\n",
		parser.sysexCount, parser.lastSysexLength, parser.shortCount,
		parser.realtimeCount, parser.debugCount);
#ifdef WIRE_VICTIM
	printInitial();
	printVictim("after");
#endif
	return 0;
}
